import { IOptions, ModuleBase, ModulesStoreType, PluginBase } from 'ninsho-base'
import { DeepPartial, mergeDeep } from 'ninsho-utils'

import { convertOneTimeTokenToHash, createOneTimeToken, verifyOneTimeToken } from './service-otp'
import { JWTSign, JWTVerify } from './service-jwt'
import { CreateUser2faFirst } from './feat-create-first'
import { CreateUser2faVerify } from './feat-create-verify'
import { ChangeEmail2faFirst } from './feat-change-email-first'
import { ChangeEmail2faVerify } from './feat-change-email-verify'
import { DeleteUser2faFirst } from './feat-delete-first'
import { DeleteUser2faVerify } from './feat-delete-verify'
import { LoginUser2faFirst } from './feat-login-first'
import { LoginUser2faVerify } from './feat-login-verify'
import { ResetPassword2faFirst } from './feat-reset-password-first'
import { ResetPassword2faSecond } from './feat-reset-password-second'
import { resetPassword2faVerify } from './feat-reset-password-verify'

// - Code required for each plugin -
const pluginName = 'Standard2faAPI' // plugin Name
const dependencyModules = ['pool', 'mailer', 'secure'] as const // Required Modules Name

// - boiler plate - Specify types only for the modules being used.
export type LendOfHere = {
  options: IOptions,
  modules: Pick<ModulesStoreType, typeof dependencyModules[number]>,
}

export type Standard2faAPIConfig = {
  secretKey: string,
  JWTSection: {
    N0_CREATE_USER: number | string | symbol,
    N1_SIGN_IN: number | string | symbol,
    N2_PASSWORD_RESET: number | string | symbol,
    N3_PASSWORD_BID: number | string | symbol,
    N5_EMAIL_UPDATE: number | string | symbol,
    N6_DELETE_MEMBER: number | string | symbol
  },
  JWTSecretKey: string,
  JWTExpirationSec: number,
  oneTimePasswordSaltRounds: number,
  jwtFuncSign: typeof JWTSign,
  jwtFuncVerify: typeof JWTVerify,
  otpFuncOfCreateOneTimeToken: typeof createOneTimeToken,
  otpFuncOfConvertOneTimeTokenToHash: typeof convertOneTimeTokenToHash,
  otpFuncOfVerifyOneTimeToken: typeof verifyOneTimeToken
}

const defaultConfig: Standard2faAPIConfig = {
  // sessionExpirationSec: 86400,
  secretKey: 'default_secret_key',
  JWTSection: {
    N0_CREATE_USER: 100,
    N1_SIGN_IN: 200,
    N2_PASSWORD_RESET: 300,
    N3_PASSWORD_BID: 400,
    N5_EMAIL_UPDATE: 600,
    N6_DELETE_MEMBER: 700
  },
  JWTSecretKey: 'default_secret_key',
  JWTExpirationSec: 600,
  oneTimePasswordSaltRounds: 10,
  jwtFuncSign: JWTSign,
  jwtFuncVerify: JWTVerify,
  otpFuncOfCreateOneTimeToken: createOneTimeToken,
  otpFuncOfConvertOneTimeTokenToHash: convertOneTimeTokenToHash,
  otpFuncOfVerifyOneTimeToken: verifyOneTimeToken
}

export class Standard2faAPI extends PluginBase {

  // - boiler template - 
  readonly pluginName = pluginName

  // - boiler template - store modules
  setModules(
    modules: { [keys: string]: ModuleBase | IOptions }
  ): Omit<this, 'pluginName' | 'config' | 'setModules'> {
    this.storeModules(modules, pluginName, dependencyModules)
    return this
  }

  // - plugin specific options -
  config = {} as Standard2faAPIConfig
  /* istanbul ignore next */
  static init(options: DeepPartial<Standard2faAPIConfig> = {}) {
    const instance = new this()
    instance.config = mergeDeep(defaultConfig, options) as Standard2faAPIConfig

    if (instance.config.secretKey === 'default_secret_key'
    || !instance.config.secretKey
    ) /* istanbul ignore next */ {
      console.log(innerError.NoSetSecretKey)
    }

    return instance
  }

  changeEmail2faFirst = ChangeEmail2faFirst.init(this.lend, this.config)
  changeEmail2faVerify = ChangeEmail2faVerify.init(this.lend, this.config)
  createUser2faFirst = CreateUser2faFirst.init(this.lend, this.config)
  createUser2faVerify = CreateUser2faVerify.init(this.lend, this.config)
  deleteUser2faFirst = DeleteUser2faFirst.init(this.lend, this.config)
  deleteUser2faVerify = DeleteUser2faVerify.init(this.lend, this.config)
  login2faFirst = LoginUser2faFirst.init(this.lend, this.config)
  login2faVerify = LoginUser2faVerify.init(this.lend, this.config)
  resetPasswordFirst = ResetPassword2faFirst.init(this.lend, this.config)
  resetPasswordSecond = ResetPassword2faSecond.init(this.lend, this.config)
  resetPasswordVerify = resetPassword2faVerify.init(this.lend, this.config)
}

const innerError = {
  NoSetSecretKey: `\x1b[31mWARNING                             
| Secret key not updated, your system's vulnerable to threats.
| Update your secret key now, ensure system safety and integrity.
| The secret key can be changed by setting options during initialization.
| StandardAPI.init({ secretKey: '....' })\x1b[0m`
}
