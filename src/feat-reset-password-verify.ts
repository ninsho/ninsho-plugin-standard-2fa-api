import { MStatus, MemberInsert, SessionInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { calibrationOfColumnsForMembers } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'
import { upsertSessionRowWithReturnedSessionToken } from './service-data'
import { jwtClaim } from './service-jwt'

export class resetPassword2faVerify {

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
    alternateToken: string,
    newPassword: string,
    ip: string,
    sessionDevice: string,
    options?: {
      // rolePermissionLevel?: number,
      userAgent?: string,
      forceAllLogout?: boolean,
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
  }, void, E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      alternateToken,
      newPassword,
      ip,
      sessionDevice,
      options: {
        // rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        forceAllLogout: options?.forceAllLogout === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.ResetPasswordCompleat.subject,
          body: options?.mailFormat?.body ?? mailFormat.ResetPasswordCompleat.body,
        },
        columnToRetrieve: calibrationOfColumnsForMembers(options?.columnToRetrieve, [
          'id',
          'm_role',
          'm_status',
          'm_name',
          'm_mail',
          'version'
        ]),
        hooks: options?.hooks
      },
    }

    let claims: jwtClaim = {} as jwtClaim
    try {
      claims = this.config.jwtFuncVerify(
        req.alternateToken,
        this.config.JWTSection.N3_PASSWORD_BID,
        this.config.JWTSecretKey
      )
    } catch (e) {
      return new E401(2384)
    }

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      {
        m_name: claims.m_name
      },
      'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(2385)
    // if (sel.response.m_role < req.options.rolePermissionLevel) return new E403(2386)
    if (sel.response.m_status != MStatus.ACTIVE) return new E403(2387)

    // update password

    const connection = await lend.modules.pool.beginWithClient()

    const upd = await lend.modules.pool.updateOneOrThrow<MemberInsert>(
      {
        m_pass: lend.modules.secure.toHashForPassword(req.newPassword)
      },
      {
        m_name: claims.m_name,
        version: sel.response.version
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) return upd.pushReplyCode(2388)

    // Logout all

    if (req.options.forceAllLogout) {
      const del = await lend.modules.pool.delete<SessionInsert>(
        { m_name: claims.m_name },
        lend.options.tableName.sessions,
        connection)
      /* istanbul ignore if */
      if (del.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return del.pushReplyCode(2389)
      }
    }

    // create session
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
      return ups.pushReplyCode(2390)
    }
    const newSessionToken = ups.response.sessionToken

    // hook:onTransactionLast
    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: sel.response,
        others: claims,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2391) as any
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
        return new E500(2392)
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
