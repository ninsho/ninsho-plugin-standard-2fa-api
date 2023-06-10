import { MStatus, MemberInsert, MembersCol, SessionCol, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult, HooksObjType, hookCall } from 'ninsho-base'
import { getNowUnixTime, calibrationOfColumnsForMix } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'
import { jwtClaim } from './service-jwt'
import { upsertSessionRowWithReturnedSessionToken } from './service-data'

export class ChangeEmail2faVerify {

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
  ): Promise<IApiResult<{
    session_token: string
  } | null, void, E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      oneTimePassword,
      alternateToken,
      sessionToken,
      ip,
      sessionDevice,
      options: {
        // rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        forceAllLogout: options?.forceAllLogout === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.ChangeEmailCompleat.subject,
          body: options?.mailFormat?.body ?? mailFormat.ChangeEmailCompleat.body,
        },
        columnToRetrieve: calibrationOfColumnsForMix(options?.columnToRetrieve, [
          'members.id',
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
        this.config.JWTSection.N5_EMAIL_UPDATE,
        this.config.JWTSecretKey
      )
    } catch (e) {
      return new E401(2309)
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
    /* istanbul ignore if */
    if (session.fail()) return session.pushReplyCode(2310)
    if (session.response.m_status != MStatus.ACTIVE) return new E403(2311)
    if (claims.version != session.response.version) return new E401(2312)

    // hook:beforePasswordCheck
    if (req.options.hooks) {
      const res = await hookCall('beforePasswordCheck', lend, {
        req: {
          ...req,
        },
        props: session.response,
        others
      })
      if (res.fail()) return res.pushReplyCode(2313) as any
    }

    // Inspect OTP

    if (!others.otpChecked) {
      const isValidOTP = this.config.otpFuncOfVerifyOneTimeToken(
        req.oneTimePassword, session.response.otp_hash as string
      )
      if (!isValidOTP) return new E401(2315)
    }

    // update email

    const connection = await lend.modules.pool.beginWithClient()

    const upd = await lend.modules.pool.updateOneOrThrow<MemberInsert>(
      {
        m_mail: claims.m_mail
      },
      {
        m_name: claims.m_name,
        version: session.response.version
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) return upd.pushReplyCode(2316)

    // Logout all

    let newSessionToken = ''
    if (req.options.forceAllLogout) {

      const del = await lend.modules.pool.delete<SessionInsert>(
        {
          m_name: claims.m_name
        },
        lend.options.tableName.sessions,
        connection)
      /* istanbul ignore if */
      if (del.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return del.pushReplyCode(2317)
      }

      // recreate session
      const ups = await upsertSessionRowWithReturnedSessionToken(
        lend,
        session.response.id,
        claims.m_role,
        claims.m_name,
        ip,
        sessionDevice,
        connection
      )
      /* istanbul ignore if */
      if (ups.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return ups.pushReplyCode(2318)
      }
      newSessionToken = ups.response.sessionToken
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
        return res.pushReplyCode(2319) as any
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
        return new E500(2320)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return /* istanbul ignore next */ req.options.forceAllLogout
      ? new ApiSuccess(
        200,
        {
          session_token: newSessionToken
        }
      )
      : new ApiSuccess(
        204,
        null
      )
  }
}
