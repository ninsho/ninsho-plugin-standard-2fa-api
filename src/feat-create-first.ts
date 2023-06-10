import { MRole, MStatus, MemberInsert, ApiSuccess, E409, E500, IApiResult, HooksObjType, hookCall } from 'ninsho-base'
import { mailFormat } from './format-email'
import { LendOfHere, Standard2faAPIConfig } from './plugin-standard-2fa-api'

export class CreateUser2faFirst {

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
    name: string,
    mail: string,
    pass: string,
    ip: string,
    m_custom: MCustom,
    options?: {
      role?: number,
      userAgent?: string,
      sendCompleatNotice?: boolean,
      mailFormat?: {
        subject?: string,
        body?: string
      },
      hooks?: HooksObjType[]
    }
  ): Promise<IApiResult<{
    alternate_token: string
  }, {
    one_time_password: string
  }, E500 | E409>> {

    const lend = this.lend
    const req = {
      name,
      mail,
      pass,
      ip,
      m_custom,
      options: {
        userAgent: options?.userAgent || '',
        sendCompleatNotice: options?.sendCompleatNotice === false ? false : true,
        role: options?.role ?? MRole.User,
        mailFormat: {
          subject: options?.mailFormat?.subject ?? mailFormat.CreateOTP.subject,
          body: options?.mailFormat?.body ?? mailFormat.CreateOTP.body,
        },
        hooks: options?.hooks
      }
    }

    const alternate_token = this.config.jwtFuncSign( // JWTSign()
      req.name,
      req.mail,
      this.config.JWTSection.N0_CREATE_USER,
      null,
      this.config.JWTExpirationSec,
      req.options.role,
      this.config.JWTSecretKey,
    )

    const one_time_password = this.config.otpFuncOfCreateOneTimeToken()

    const connection = await lend.modules.pool.beginWithClient()

    const ins = await lend.modules.pool.replaceOneWithConditionExistAndDeadLine<MemberInsert>(
      {
        m_name: req.name,
        m_pass: lend.modules.secure.toHashForPassword(req.pass),
        m_mail: req.mail,
        m_custom: req.m_custom,
        m_role: req.options.role,
        m_ip: req.ip,
        otp_hash: this.config.otpFuncOfConvertOneTimeTokenToHash(
          one_time_password, this.config.oneTimePasswordSaltRounds
        ),
        m_status: MStatus.PENDING
      },
      lend.options.tableName.members,
      this.config.JWTExpirationSec, // rewrite release threshold
      connection)
    if (ins.fail()) {
      await lend.modules.pool.rollbackWithRelease(connection)
      return ins.pushReplyCode(2321)
    }

    if (req.options.hooks) {
      const res = await hookCall('onTransactionLast', lend, {
        req,
        connection,
        others: {
          alternate_token,
          one_time_password
        }
      })
      if (res.fail()) {
        await lend.modules.pool.rollbackWithRelease(connection)
        return res.pushReplyCode(2322) as any
      }
    }

    if (req.options.sendCompleatNotice) {
      try {
        await lend.modules.mailer.sender(
          req.mail,
          req.options.mailFormat.subject,
          req.options.mailFormat.body,
          {
            ...req,
            ...{
              one_time_password: one_time_password
            }
          }
        )
      } catch (e) /* istanbul ignore next */ {
        await lend.modules.pool.rollbackWithRelease(connection)
        return new E500(2323)
      }
    }

    await lend.modules.pool.commitWithRelease(connection)

    return new ApiSuccess(
      201,
      {
        alternate_token
      },
      {
        one_time_password
      }
    )

  }
}
