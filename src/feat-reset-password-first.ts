
import { MRole, MStatus, MemberInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { calibrationOfColumnsForMembers } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { Standard2faAPIConfig, LendOfHere } from './plugin-standard-2fa-api'

export class ResetPassword2faFirst{

  // - boiler plate -
  lend = {} as LendOfHere
  config = {} as Standard2faAPIConfig
  static init(lend: LendOfHere, config: Standard2faAPIConfig) {
    const instance = new this()
    instance.lend = lend
    instance.config = config
    return instance.method
  }

  private async method<MCustom>(
    name: string | undefined | null,
    mail: string | undefined | null,
    ip: string,
    options?: {
      rolePermissionLevel?: number,
      userAgent?: string,
      sendResetURLNotice?: boolean,
      mailFormat?: {
        subject?: string,
        body?: string
      },
      columnToRetrieve?: (keyof MemberInsert)[] | '*',
      hooks?: HooksObjType[],
      m_custom?: MCustom
    }
  ): Promise<IApiResult<
    null,
    {
      alternate_token: string
    },
    E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      name: name === '' || !name ? undefined : name,
      mail: mail === '' || !mail ? undefined : mail,
      ip,
      options: {
        rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        userAgent: options?.userAgent || '',
        sendResetURLNotice: options?.sendResetURLNotice === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.ResetPasswordSendToken.subject,
          body: options?.mailFormat?.body ?? mailFormat.ResetPasswordSendToken.body,
        },
        columnToRetrieve: calibrationOfColumnsForMembers(options?.columnToRetrieve, [
          'm_role',
          'm_status',
          'm_name',
          'm_mail',
          'version'
        ]),
        hooks: options?.hooks,
        m_custom: options?.m_custom || {},
      }
    }

    const conditionSet: { m_name?: string, m_mail?: string } = {}
    if (req.name) conditionSet.m_name = req.name
    if (req.mail) conditionSet.m_mail = req.mail
    if (!Object.keys(conditionSet).length) return new E400(2395)

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      conditionSet,
      'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(2374)
    if (sel.response.m_role < req.options.rolePermissionLevel) return new E403(2375)
    if (sel.response.m_status != MStatus.ACTIVE) return new E403(2376)

    // create JWT
    const alternate_token = this.config.jwtFuncSign(
      sel.response.m_name,
      sel.response.m_mail,
      this.config.JWTSection.N2_PASSWORD_RESET,
      sel.response.version,
      this.config.JWTExpirationSec,
      sel.response.m_role,
      this.config.JWTSecretKey,
    )

    const connection = await lend.modules.pool.beginWithClient()

    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: sel.response,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2378) as any
      }
    }

    if (req.options.sendResetURLNotice) {
      try {
        await lend.modules.mailer.sender(
          sel.response.m_mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              name: sel.response.m_name,
              jwt_token: alternate_token  
            }
          }
        )
      } catch (e) /* istanbul ignore next */ {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2379)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      204,
      null,
      {
        alternate_token
      }
    )
  }
}
