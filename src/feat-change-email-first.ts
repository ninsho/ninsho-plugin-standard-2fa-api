import { MRole, MStatus, MemberInsert, MembersCol, SessionCol, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult, HooksObjType, hookCall } from 'ninsho-base'
import { getNowUnixTime, calibrationOfColumnsForMix } from 'ninsho-utils'
import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'

export class ChangeEmail2faFirst {

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
    newEmail: string,
    ip: string,
    sessionDevice: string,
    options?: {
      pass?: string,
      rolePermissionLevel?: number,
      userAgent?: string,
      sendOTPNotice?: boolean,
      forceAllLogout?: boolean,
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
      newEmail,
      ip,
      sessionDevice,
      options: {
        pass: options?.pass, // Ninsho checks passwords only when there is a password
        rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendOTPNotice: options?.sendOTPNotice === false ? false : true,
        forceAllLogout: options?.forceAllLogout === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.ChangeEmailOTPNewEmail.subject,
          body: options?.mailFormat?.body ?? mailFormat.ChangeEmailOTPNewEmail.body,
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
    if (session.fail()) return session.pushReplyCode(2300)
    if (session.response.m_role < req.options.rolePermissionLevel) return new E403(2301)
    if (session.response.m_status != MStatus.ACTIVE) return new E403(2302)
    if (req.newEmail === session.response.m_mail) return new E400(2303)

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
      if (res.fail()) return res.pushReplyCode(2304) as any
    }

    // ..Inspect Session
    if (req.options.pass
      && !others.passwordChecked
      && !lend.modules.secure.checkHashPassword(req.options.pass, session.response.m_pass))
      return new E401(2305)

    // create JWT
    const alternate_token = this.config.jwtFuncSign(
      session.response.m_name,
      req.newEmail,
      this.config.JWTSection.N5_EMAIL_UPDATE,
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
        version: session.response.version
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return upd.pushReplyCode(2306)
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
        return res.pushReplyCode(2307) as any
      }
    }

    // notifier

    if (req.options.sendOTPNotice) {
      try {
        await lend.modules.mailer.sender(
          req.newEmail,
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
        return new E500(2308)
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
