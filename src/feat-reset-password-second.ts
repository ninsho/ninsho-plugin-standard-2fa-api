
import { MStatus, MemberInsert } from 'ninsho-base'
import { ApiSuccess, E400, E401, E403, E404, E500, IApiResult } from 'ninsho-base'
import { Standard2faAPIConfig, LendOfHere } from './plugin-standard-2fa-api'
import { jwtClaim } from './service-jwt'

export class ResetPassword2faSecond{

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
    alternateToken: string
  ): Promise<IApiResult<
    {
      alternate_token: string
    },
    void,
    E400 | E401 | E403 | E404 | E500>> {

    const lend = this.lend
    const req = {
      alternateToken,
      options: {
        columnToRetrieve: [ 
          'm_role',
          'm_status',
          'm_name',
          'm_mail',
          'version'
        ] as (keyof MemberInsert)[],
      }
    }

    let claims: jwtClaim = {} as jwtClaim
    try {
      claims = this.config.jwtFuncVerify(
        req.alternateToken,
        this.config.JWTSection.N2_PASSWORD_RESET,
        this.config.JWTSecretKey
      )
    } catch (e) {
      return new E401(2380)
    }

    const sel = await lend.modules.pool.selectOneOrThrow<MemberInsert>(
      lend.options.tableName.members,
      req.options.columnToRetrieve,
      {
        m_name: claims.m_name
      },
      'AND'
    )
    if (sel.fail()) return sel.pushReplyCode(2381)
    if (sel.response.m_status != MStatus.ACTIVE) return new E401(2383)

    // create JWT
    const alternate_token = this.config.jwtFuncSign(
      sel.response.m_name,
      sel.response.m_mail,
      this.config.JWTSection.N3_PASSWORD_BID,
      sel.response.version,
      this.config.JWTExpirationSec,
      sel.response.m_role,
      this.config.JWTSecretKey,
    )

    return new ApiSuccess(
      200,
      {
        alternate_token
      }
    )
  }
}
