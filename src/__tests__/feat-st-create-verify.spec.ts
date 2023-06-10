import { MemberInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

const { pool, plugin } = initializeLocalPlugin()

describe('st-create-verify', () => {

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

  const create = async () => {
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
    return res_first
  }

  // =====
  // ===== test
  // =====

  it('200: Positive case', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('401: jwt', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token + 'XXX',
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('200: hook: onTransactionLast', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice, {
      hooks: [
        {
          hookPoint: 'onTransactionLast',
          hook: TestHook()
        }
      ]
    }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('500: fail hook: onTransactionLast', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice, {
      hooks: [
        {
          hookPoint: 'onTransactionLast',
          hook: TestHookFail()
        }
      ]
    }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(500)
  })

  it('403: role', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice,
      {
        rolePermissionLevel: 1
      }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('200: sendCompleatNotice', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('200: mail format', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice,
      {
        mailFormat: {
          subject: 'Dear {{name}} verify subject',
          body: 'Dear {{name}} verify body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user verify subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user verify body')
  })

  it('404: no data', async () => {
    const res1_create = await create()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ m_name: "XXX" }, { m_mail: user.mail }, 'AND', 'members')
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice,
      {}
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('403: role', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice,
      {
        rolePermissionLevel: 1
      }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('401: otp null', async () => {
    const res1_create = await create()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ otp_hash: null }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.createUser2faVerify(
      null as any,
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
    expect(res1.body.replyCode).toEqual([ 2326 ])
  })

  it('401: otp', async () => {
    const res1_create = await create()
    // test
    const res1 = await plugin.createUser2faVerify(
      res1_create.system.one_time_password + 'XXX',
      res1_create.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

})
