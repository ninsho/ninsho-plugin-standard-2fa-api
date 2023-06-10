import { MRole, MStatus, MemberInsert, MembersCol, SessionCol, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult, HooksObjType, hookCall } from 'ninsho-base'
import { getNowUnixTime, calibrationOfColumnsForMix } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'

export class DeleteUser2faFirst {

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
    sessionToken: string,
    ip: string,
    sessionDevice: string,
    options?: {
      pass?: string,
      rolePermissionLevel?: number,
      userAgent?: string,
      sendOTPNotice?: boolean,
      mailFormat?: {
        subject?: string,
        body?: string
      },
      columnToRetrieve?: (MembersCol | SessionCol)[] | '*',
      hooks?: HooksObjType[]
    }
  ): Promise<IApiResult<{
    alternate_token: string
  }, {
    one_time_password: string
  }, E400 | E401 | E403 | E404 | E500>> {

    const others = { passwordChecked: false }
    const lend = this.lend
    const req = {
      sessionToken,
      ip,
      sessionDevice,
      options: {
        pass: options?.pass, // Ninsho checks passwords only when there is a password
        // physical_deletion: options?.physical_deletion === false ? false : true,
        // overwritePossibleOnLogicallyDeletedData: options?.overwritePossibleOnLogicallyDeletedData === false ? false : true,
        rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendOTPNotice: options?.sendOTPNotice === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.deletionOTP.subject,
          body: options?.mailFormat?.body ?? mailFormat.deletionOTP.body,
        },
        columnToRetrieve: calibrationOfColumnsForMix(options?.columnToRetrieve, [
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

    // Inspect Session

    const session = await lend.modules.pool.retrieveMemberIfSessionPresentOne<MemberInsert & SessionInsert>(
      lend.modules.secure.toHashForSessionToken(req.sessionToken),
      getNowUnixTime() - lend.options.sessionExpirationSec,
      req.sessionDevice,
      req.ip,
      req.options.columnToRetrieve
    )
    /* istanbul ignore if */ 
    if (session.fail()) return session.pushReplyCode(2331)
    if (session.response.m_role < req.options.rolePermissionLevel) return new E403(2332)
    if (session.response.m_status != MStatus.ACTIVE) return new E403(2333)

    // hook:beforePasswordCheck
    if (req.options.hooks) {
      const res = await hookCall('beforePasswordCheck', lend, {
        req: {
          ...req,
          ...{
            name: session.response.m_name
          }
        },
        props: session.response,
        others
      })
      if (res.fail()) return res.pushReplyCode(2334) as any
    }

    // ..Inspect Session
    if (req.options.pass
      && !others.passwordChecked
      && !lend.modules.secure.checkHashPassword(req.options.pass, session.response.m_pass))
      return new E401(2335)

    // create JWT
    const alternate_token = this.config.jwtFuncSign(
      session.response.m_name,
      session.response.m_mail,
      this.config.JWTSection.N6_DELETE_MEMBER,
      session.response.version + 1,
      this.config.JWTExpirationSec,
      session.response.m_role,
      this.config.JWTSecretKey,
    )

    const one_time_password = this.config.otpFuncOfCreateOneTimeToken()

    const connection = await lend.modules.pool.beginWithClient()

    // Store OTP

    const upd = await lend.modules.pool.updateOneOrThrow<MemberInsert>(
      {
        otp_hash: this.config.otpFuncOfConvertOneTimeTokenToHash(
          one_time_password, this.config.oneTimePasswordSaltRounds
        )
      },
      {
        m_name: session.response.m_name,
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return upd.pushReplyCode(2336)
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
        return res.pushReplyCode(2337) as any
      }
    }

    // notifier

    if (req.options.sendOTPNotice) {
      try {
        await lend.modules.mailer.sender(
          session.response.m_mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              name: session.response.m_name,
              one_time_password: one_time_password
            }
          }
        )
      } catch (e) /* istanbul ignore next */ {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2338)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      200,
      {
        alternate_token
      },
      {
        one_time_password
      }
    )
  }
}
