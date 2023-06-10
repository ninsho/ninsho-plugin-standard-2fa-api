import { MemberInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

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
    return res_verify
  }

  // =====
  // ===== test
  // =====

  it('200: Positive case', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('401: bad name', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name + 'XXX',
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('404: bad email', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail + 'XXX',
      user.pass,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('401: bad password', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass + 'XXX',
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('200: hook: beforePasswordCheck', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice, {
        hooks: [
          {
            hookPoint: 'beforePasswordCheck',
            hook: TestHook()
          }
        ]
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('500: fail hook: beforePasswordCheck', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice, {
        hooks: [
          {
            hookPoint: 'beforePasswordCheck',
            hook: TestHookFail()
          }
        ]
      }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(500)
  })

  it('200: hook: onTransactionLast', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
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
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
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
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
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
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
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
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: true,
        mailFormat: {
          subject: 'Dear {{name}} login first subject',
          body: 'Dear {{name}} login first body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user login first subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user login first body')
  })

  it('400: name/mail null', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.login2faFirst(
      '',
      '',
      user.pass,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false
      }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(400)
  })

  it('403: status', async () => {
    const res1_created = await created()
    // brake
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })


})
