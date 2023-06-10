import { Standard2faAPI } from '../plugin-standard-2fa-api'
import { JWTSign } from '../service-jwt'
import { initializeLocalPlugin } from './x-service'

const { plugin } = initializeLocalPlugin()

describe('st-login-first', () => {

  const user = {
    name: 'test_user',
    mail: 'test@localhost_com',
    pass: 'test1234',
    ip: '127.0.0.1',
    sessionDevice: 'test-client',
    view_name: 'is test view',
    tel: '000-0000-0001'
  }

  type MCustomT = Partial<{
    view_name: string,
    tel: string
  }>

  // =====
  // ===== test
  // =====

  it('204: Positive case', async () => {
    const jwt = JWTSign(
      user.name,
      user.mail,
      'BAD SECTION',
      999,
      3600,
      0,
      'default_secret_key'
    )

    const res = await plugin.createUser2faVerify(
      "999999",
      jwt,
      user.ip,
      user.sessionDevice
    )
    if (!!!res.fail()) throw 1
    expect(res.body.replyCode).toEqual([ 2324 ])
  })

  it('204: Positive case', async () => {
    const api = Standard2faAPI.init({})
    expect(api.config.JWTSecretKey).toEqual('default_secret_key')
  })
})
