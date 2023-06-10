import { MemberInsert, SessionInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'
import { matchForUUID } from './x-utils'

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

  const loginFirst = async () => {
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
    const res1_login_first = await plugin.login2faFirst(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      user.sessionDevice
    )
    if (res1_login_first.fail()) throw 300
    return res1_login_first
  }

  // =====
  // ===== test
  // =====

  it('200: Positive case', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    expect(res1.body).toEqual(expect.objectContaining({ session_token: matchForUUID }))
  })

  it('401: jwt', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token + 'XXX',
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('200: Positive case', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    expect(res1.body).toEqual(expect.objectContaining({ session_token: matchForUUID }))
  })

  it('200: hook: beforePasswordCheck', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
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
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      // session_token,
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
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      // session_token,
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
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      // session_token,
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

  it('200: sendCompleatNotice', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      // session_token,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false
      }
    )
    if (res1.fail()) { console.log(res1.body); throw 1 }
    expect(res1.statusCode).toEqual(200)
    // expect
    const db = await pool.select<SessionInsert>('sessions', ['m_name'], { m_role: 0 })
    if (db.fail()) throw 2
    expect(db.response.rowCount).toEqual(1)
  })

  it('200: forceAllLogout', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      '111.111.111.111',
      user.sessionDevice,
      {
        forceAllLogout: false
      }
    )
    if (res1.fail()) { console.log(res1.body); throw 1 }
    // expect
    expect(res1.statusCode).toEqual(200)
    // expect
    const db = await pool.select<SessionInsert>('sessions', ['m_name'], { m_role: 0 })
    if (db.fail()) throw 2
    expect(db.response.rowCount).toEqual(2)
  })


  it('200: mail format', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      '111.111.111.111',
      user.sessionDevice,
      {
        mailFormat: {
          subject: 'Dear {{name}} login verify subject',
          body: 'Dear {{name}} login verify body'
        }
      }
    )
    if (res1.fail()) { console.log(res1.body); throw 1 }
    // expect
    expect(res1.statusCode).toEqual(200)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user login verify subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user login verify body')
  })

  it('404: no data', async () => {
    const res_first = await loginFirst()
    // brake
    const db = await pool.delete({ m_name: user.name }, 'members')
    if (db.fail()) throw 1
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 2
    expect(res1.statusCode).toEqual(404)
  })

  it('403: status', async () => {
    const res_first = await loginFirst()
    // brake
    const db = await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name }, 'AND', 'members')
    if (db.fail()) throw 1
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 2
    expect(res1.statusCode).toEqual(403)
  })

  it('401: otp null', async () => {
    const res_first = await loginFirst()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ otp_hash: null, version: 1 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password,
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) { console.log(res1.body); throw 1 }
    expect(res1.statusCode).toEqual(500)
    expect(res1.body.replyCode).toEqual([ 2366 ])
  })

  it('401: otp', async () => {
    const res_first = await loginFirst()
    // test
    const res1 = await plugin.login2faVerify(
      res_first.system.one_time_password + 'XXX',
      res_first.body.alternate_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) { console.log(res1.body); throw 1 }
    expect(res1.statusCode).toEqual(401)
  })

})