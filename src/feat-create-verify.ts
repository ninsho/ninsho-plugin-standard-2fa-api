import { MRole, MStatus, MemberInsert, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E401, E403, E404, E409, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { getNowUnixTime, calibrationOfColumnsForMembers } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'
import { jwtClaim } from './service-jwt'

export class CreateUser2faVerify {

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
    ip: string,
    sessionDevice: string,
    options?: {
      rolePermissionLevel?: number,
      userAgent?: string,
      sendCompleatNotice?: boolean,
      mailFormat?: {
        subject?: string,
        body?: string
      },
      columnToRetrieve?: (keyof MemberInsert)[] | '*',
      hooks?: HooksObjType[]
    }
  ): Promise<IApiResult<{
    session_token: string
  }, void, E500 | E401 | E403 | E404 | E409>> {

    const lend = this.lend
    const req = {
      alternateToken,
      oneTimePassword,
      sessionDevice,
      ip,
      options: {
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.CreateCompleat.subject,
          body: options?.mailFormat?.body ?? mailFormat.CreateCompleat.body
        },
        columnToRetrieve: calibrationOfColumnsForMembers(options?.columnToRetrieve, [
          'otp_hash',
          'm_role'
        ]),
        hooks: options?.hooks
      }
    }

    let claims = {} as jwtClaim
    try {
      claims = this.config.jwtFuncVerify(
        req.alternateToken,
        this.config.JWTSection.N0_CREATE_USER,
        this.config.JWTSecretKey)
    } catch (e) {
      return new E401(2324)
    }

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      {
        m_name: claims.m_name
      },
      'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(2325)
    if (sel.response.m_role < req.options.rolePermissionLevel) return new E403(2393)
    if (!sel.response.otp_hash) return new E401(2326)

    const isValidPassword = this.config.otpFuncOfVerifyOneTimeToken(
      req.oneTimePassword, sel.response.otp_hash)
    if (!isValidPassword) return new E401(2327)

    const connection = await lend.modules.pool.beginWithClient()

    const upd = await lend.modules.pool.updateOneOrThrow<MemberInsert>(
      {
        m_ip: req.ip,
        m_status: MStatus.ACTIVE,
        otp_hash: null,
      },
      {
        m_name: claims.m_name,
        m_status: MStatus.PENDING
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return upd.pushReplyCode(2328)
    }

    const { sessionToken, hashToken } = lend.modules.secure.createSessionTokenWithHash()

    const insSession = await lend.modules.pool.insertOne<SessionInsert>(
      {
        members_id: upd.response.rows[0].id,
        m_name: claims.m_name,
        m_ip: req.ip,
        m_device: req.sessionDevice,
        created_time: getNowUnixTime(),
        token: hashToken,
        m_role: claims.m_role
      },
      lend.options.tableName.sessions,
      connection)
    /* istanbul ignore if */
    if (insSession.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return insSession.pushReplyCode(2329)
    }

    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: sel.response,
        claims,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2330) as any
      }
    }

    if (req.options.sendCompleatNotice) {
      try {
        await lend.modules.mailer.sender(
          claims.m_mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              sessionToken: sessionToken,
              name: claims.m_name
            }
          }
        )
      } catch (e) /* istanbul ignore next */ {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2331)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      200,
      {
        session_token: sessionToken
      }
    )

  }
}
