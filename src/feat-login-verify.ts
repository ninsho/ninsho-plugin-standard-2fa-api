import { MStatus, MemberInsert, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { calibrationOfColumnsForMembers } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'
import { jwtClaim } from './service-jwt'
import { upsertSessionRowWithReturnedSessionToken } from './service-data'

export class LoginUser2faVerify {

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
    // sessionToken: string,
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
      columnToRetrieve?: (keyof MemberInsert)[] | '*',
      hooks?: HooksObjType[]
    }
  ): Promise<IApiResult<{
    session_token: string
  }, void, E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      oneTimePassword,
      alternateToken,
      // sessionToken,
      ip,
      sessionDevice,
      options: {
        // rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        forceAllLogout: options?.forceAllLogout === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.loginCompleat.subject,
          body: options?.mailFormat?.body ?? mailFormat.loginCompleat.body,
        },
        columnToRetrieve: calibrationOfColumnsForMembers(options?.columnToRetrieve, [
          'id',
          'otp_hash',
          'm_name',
          'm_mail',
          'm_pass',
          'm_role',
          'm_status',
          'version'
        ]),
        hooks: options?.hooks
      },
    }

    let claims: jwtClaim = {} as jwtClaim
    try {
      claims = this.config.jwtFuncVerify(
        req.alternateToken,
        this.config.JWTSection.N1_SIGN_IN,
        this.config.JWTSecretKey
      )
    } catch (e) {
      return new E401(2361)
    }

    const others = { otpChecked: false, claims }

    if (req.options.hooks) {
      const res = await hookCall('beforePasswordCheck', lend, {
        req: {
          ...req,
        },
        // props: sel.response,
        others: claims
      })
      if (res.fail()) return res.pushReplyCode(2365) as any
    }

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      { m_name: claims.m_name },
      'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(9999)
    if (sel.response.m_status != MStatus.ACTIVE) return new E403(9999)

    // Inspect OTP

    if (!others.otpChecked) {
      if (sel.response.otp_hash === null) return new E500(2366)
      const isValidOTP = this.config.otpFuncOfVerifyOneTimeToken(
        req.oneTimePassword, sel.response.otp_hash
      )
      if (!isValidOTP) return new E401(2367)
    }

    const connection = await lend.modules.pool.beginWithClient()

    // Logout all

    let newSessionToken = ''

    const condition: {
      m_name: string,
      m_ip?: string,
      m_device?: string
    } = {
      m_name: claims.m_name
    }
    if (!req.options.forceAllLogout) {
      condition.m_ip = req.ip
      condition.m_device = req.sessionDevice
    }

    const del = await lend.modules.pool.delete<SessionInsert>(
      condition,
      lend.options.tableName.sessions,
      connection)
    /* istanbul ignore if */ 
    if (del.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return del.pushReplyCode(2368)
    }

    // recreate session
    const ups = await upsertSessionRowWithReturnedSessionToken(
      lend,
      sel.response.id,
      claims.m_role,
      claims.m_name,
      ip,
      sessionDevice,
      connection
    )
    /* istanbul ignore if */
    if (ups.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return ups.pushReplyCode(2369)
    }
    newSessionToken = ups.response.sessionToken

    // hook:onTransactionLast
    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: sel.response,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2370) as any
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
        return new E500(2371)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      200,
      {
        session_token: newSessionToken
      }
    )
  }
}
