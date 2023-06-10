import { MemberInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

const { pool, plugin } = initializeLocalPlugin()

let session_token = ''

describe('im-change-email', () => {

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

  const changeEmailFirst = async () => {
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

    session_token = res_verify.body.session_token

    const res_change_email_first = await plugin.changeEmail2faFirst(
      session_token,
      user.newEmail,
      user.ip,
      user.sessionDevice
    )
    if (res_change_email_first.fail()) throw 300

    return res_change_email_first
  }

  // =====
  // ===== test
  // =====

  it('200: Positive case', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('401: jwt', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token + 'XXX',
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
    expect(res1.body.replyCode).toEqual([ 2309 ])
  })

  it('200: hook: beforePasswordCheck', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
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
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
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
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
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
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
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

  it('200: forceAllLogout', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        forceAllLogout: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
  })

  it('403: status', async () => {
    const res1_emf = await changeEmailFirst()
    // brake
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name}, 'AND', 'members')
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('401: version', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    const res2 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      res1.body?.session_token as string,
      user.ip,
      user.sessionDevice
    )
    if (!!!res2.fail()) throw 1
    expect(res2.statusCode).toEqual(401)
    expect(res2.body.replyCode).toEqual([ 2312 ])
  })

  it('401: otp', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password + 'XXX',
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('200: mail format', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
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
    expect(MailerStorage[user.newEmail].mailSubject).toEqual('Dear test_user verify subject')
    expect(MailerStorage[user.newEmail].mailBody).toEqual('Dear test_user verify body')
  })

  it('200: mail format', async () => {
    const res1_emf = await changeEmailFirst()
    // test
    const res1 = await plugin.changeEmail2faVerify(
      res1_emf.system.one_time_password,
      res1_emf.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })


})