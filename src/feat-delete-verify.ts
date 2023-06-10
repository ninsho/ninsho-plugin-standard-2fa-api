import { MStatus, MemberInsert, MembersCol, SessionCol, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { getNowUnixTime, calibrationOfColumnsForMix } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'
import { jwtClaim } from './service-jwt'

export class DeleteUser2faVerify {

  // - boiler plate -
  lend = {} as LendOfHere
  config = {} as Standard2faAPIConfig
  static init(lend: LendOfHere, config: Standard2faAPIConfig) {
    const instance = new this()
    instance.lend = lend
    instance.config = config
    return instance.method
  }

  private async method(
    oneTimePassword: string,
    alternateToken: string,
    sessionToken: string,
    ip: string,
    sessionDevice: string,
    options?: {
      physical_deletion?: boolean,
      overwritePossibleOnLogicallyDeletedData?: boolean,
      // rolePermissionLevel?: number,
      userAgent?: string,
      sendCompleatNotice?: boolean,
      forceAllLogout?: boolean,
      mailFormat?: {
        subject?: string,
        body?: string
      },
      columnToRetrieve?: (MembersCol | SessionCol)[] | '*',
      hooks?: HooksObjType[]
    }
  ): Promise<IApiResult<null, void, E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      oneTimePassword,
      alternateToken,
      sessionToken,
      ip,
      sessionDevice,
      options: {
        physical_deletion: options?.physical_deletion === false ? false : true,
        overwritePossibleOnLogicallyDeletedData: options?.overwritePossibleOnLogicallyDeletedData === false ? false : true,
        // rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        forceAllLogout: options?.forceAllLogout === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.ChangeEmailCompleat.subject,
          body: options?.mailFormat?.body ?? mailFormat.ChangeEmailCompleat.body,
        },
        columnToRetrieve: calibrationOfColumnsForMix(options?.columnToRetrieve, [
          'members.otp_hash',
          'members.m_name',
          'members.m_mail',
          'members.m_pass',
          'members.m_role',
          'members.m_status',
          'members.version'
        ]),
        hooks: options?.hooks
      },
    }

    let claims: jwtClaim = {} as jwtClaim
    try {
      claims = this.config.jwtFuncVerify(
        req.alternateToken,
        this.config.JWTSection.N6_DELETE_MEMBER,
        this.config.JWTSecretKey
      )
    } catch (e) {
      return new E401(2339)
    }

    const others = { otpChecked: false, claims }

    // Inspect Session

    const session = await lend.modules.pool.retrieveMemberIfSessionPresentOne<MemberInsert & SessionInsert>(
      lend.modules.secure.toHashForSessionToken(req.sessionToken),
      getNowUnixTime() - lend.options.sessionExpirationSec,
      req.sessionDevice,
      req.ip,
      req.options.columnToRetrieve
    )
    if (session.fail()) return session.pushReplyCode(2340)
    if (session.response.m_status != MStatus.ACTIVE) return new E403(2341)
    if (claims.version != session.response.version) return new E401(2342)

    // hook:beforePasswordCheck
    if (req.options.hooks) {
      const res = await hookCall('beforePasswordCheck', lend, {
        req: {
          ...req,
        },
        props: session.response,
        others
      })
      if (res.fail()) return res.pushReplyCode(2343) as any
    }

    // Inspect OTP

    if (!others.otpChecked) {
      if (session.response.otp_hash === null) return new E500(2344)
      const isValidOTP = this.config.otpFuncOfVerifyOneTimeToken(
        req.oneTimePassword, session.response.otp_hash
      )
      if (!isValidOTP) return new E401(2345)
    }

    // delete user

    const connection = await lend.modules.pool.beginWithClient()

    if (req.options.physical_deletion) {
      const delMember = await lend.modules.pool.deleteOrThrow<MemberInsert>(
        {
          m_name: session.response.m_name
        },
        lend.options.tableName.members,
        connection)
      /* istanbul ignore if */
      if (delMember.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return delMember.pushReplyCode(2346)
      }
    } else {
      const tmpDate = new Date().getTime()
      const updMember = await lend.modules.pool.updateOneOrThrow<MemberInsert>(
        {
          m_status: MStatus.INACTIVE,
          m_name: req.options.overwritePossibleOnLogicallyDeletedData ? `${tmpDate}#${session.response.m_name}` : session.response.m_name,
          m_mail: req.options.overwritePossibleOnLogicallyDeletedData ? `${tmpDate}#${session.response.m_mail}` : session.response.m_mail,
        },
        {
          m_name: session.response.m_name,
          m_status: MStatus.ACTIVE
        },
        'AND',
        lend.options.tableName.members,
        connection)
      /* istanbul ignore if */
      if (updMember.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return updMember.pushReplyCode(2347)
      }
    }

    // Logout all

    const del = await lend.modules.pool.delete<SessionInsert>(
      { m_name: claims.m_name },
      lend.options.tableName.sessions,
      connection)
    /* istanbul ignore if */
    if (del.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return del.pushReplyCode(2348)
    }

    // hook:onTransactionLast
    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: session.response,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2349) as any
      }
    }

    // notifier

    if (req.options.sendCompleatNotice) {
      try {
        await lend.modules.mailer.sender(
          claims.m_mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              name: claims.m_name
            }
          }
        )
      } catch (e) /* istanbul ignore next */ {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2350)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      204,
      null
    )
  }
}
