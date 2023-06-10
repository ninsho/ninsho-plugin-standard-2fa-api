import { MemberInsert } from 'ninsho-base'
import { initializeLocalPlugin } from './x-service'

const { pool, plugin } = initializeLocalPlugin()

describe('st-login-first', () => {

  const user = {
    name: 'test_user',
    mail: 'test@localhost_com',
    pass: 'test1234',
    newEmail: 'new@localhost_com',
    ip: '127.0.0.1',
    sessionDevice: 'test-client',
    view_name: 'is test view',
    tel: '000-0000-0001'
  }

  type MCustomT = Partial<{
    view_name: string,
    tel: string
  }>

  const created = async () => {
    const res_first = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {
        view_name: user.view_name,
        tel: user.tel
      }
    )
    if (res_first.fail()) throw 100
    const res_verify = await plugin.createUser2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (res_verify.fail()) throw 200
    const res_reset_first = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip
    )
    if (res_reset_first.fail()) throw 300 
    return res_reset_first
  }

  // =====
  // ===== test
  // =====

  it('204: Positive case', async () => {
    const res_reset_first = await created()
    // test
    const res1 = await plugin.resetPasswordSecond(
      res_reset_first.system.alternate_token
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('401: jwt', async () => {
    const res_reset_first = await created()
    // test
    const res1 = await plugin.resetPasswordSecond(
      res_reset_first.system.alternate_token + 'XXX'
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('404: no data', async () => {
    const res_reset_first = await created()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ m_name: 'XXX' }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.resetPasswordSecond(
      res_reset_first.system.alternate_token
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('401: status', async () => {
    const res_reset_first = await created()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.resetPasswordSecond(
      res_reset_first.system.alternate_token
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

})