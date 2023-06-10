import { MRole, MStatus, MemberInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { HooksObjType, hookCall } from 'ninsho-base'
import { calibrationOfColumnsForMembers } from 'ninsho-utils'

import { mailFormat } from './format-email'
import { Standard2faAPIConfig, LendOfHere } from './plugin-standard-2fa-api'

export class LoginUser2faFirst {

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
    pass: string,
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
      hooks?: HooksObjType[],
      m_custom?: MCustom
    }
  ): Promise<IApiResult<{
    alternate_token: string
  }, {
    one_time_password: string
  }, E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      name: name === '' || !name ? undefined : name,
      mail: mail === '' || !mail ? undefined : mail,
      pass,
      ip,
      sessionDevice,
      options: {
        userAgent: options?.userAgent || '',
        rolePermissionLevel: options?.rolePermissionLevel ?? MRole.User,
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.loginOTP.subject,
          body: options?.mailFormat?.body ?? mailFormat.loginOTP.body,
        },
        columnToRetrieve: calibrationOfColumnsForMembers(options?.columnToRetrieve, [
          'm_role',
          'm_status',
          'm_name',
          'm_mail',
          'm_pass',
          'version'
        ]),
        hooks: options?.hooks,
        m_custom: options?.m_custom || {},
      }
    }

    const others = { passwordChecked: false }

    const conditionSet: { m_name?: string, m_mail?: string } = {}
    if (req.name) conditionSet.m_name = req.name
    if (req.mail) conditionSet.m_mail = req.mail
    if (!Object.keys(conditionSet).length) return new E400(2394)

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      conditionSet, 'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(2353)
    if (sel.response.m_role < req.options.rolePermissionLevel) return new E403(2354)
    if (sel.response.m_status != MStatus.ACTIVE) return new E403(2355)

    if (req.options.hooks) {
      const res = await hookCall('beforePasswordCheck', lend, {
        req,
        props: sel.response,
        others
      })
      if (res.fail()) return res.pushReplyCode(2356) as any
    }

    if (!others.passwordChecked && !lend.modules.secure.checkHashPassword(req.pass, sel.response.m_pass))
      return new E401(2357)

    // create JWT
    const alternate_token = this.config.jwtFuncSign(
      sel.response.m_name,
      sel.response.m_mail,
      this.config.JWTSection.N1_SIGN_IN,
      sel.response.version + 1,
      this.config.JWTExpirationSec,
      sel.response.m_role,
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
        m_name: sel.response.m_name,
      },
      'AND',
      lend.options.tableName.members,
      connection)
    /* istanbul ignore if */
    if (upd.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return upd.pushReplyCode(2358)
    }

    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        props: sel.response,
        connection
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2359) as any
      }
    }

    if (req.options.sendCompleatNotice) {
      try {
        await lend.modules.mailer.sender(
          sel.response.m_mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              name: sel.response.m_name,
              one_time_password: one_time_password
            }
          }
        )
      } catch (e) /* istanbul ignore next */  {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2360)
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
