import { MemberInsert, SessionInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

const { pool, plugin, secure } = initializeLocalPlugin()

describe('st-login-first', () => {

  const user = {
    name: 'test_user',
    mail: 'test@localhost_com',
    pass: 'test1234',
    newPassword: 'new.pass1234',
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

  const seconded = async () => {
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
    const res_reset_second = await plugin.resetPasswordSecond(
      res_reset_first.system.alternate_token
    )
    if (res_reset_second.fail()) throw 400
    return res_reset_second
  }

  // =====
  // ===== test
  // =====

  it('204: Positive case', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    const db = await pool.selectOneOrThrow<MemberInsert>('members', '*', { m_name: user.name }, 'AND')
    if (db.fail()) throw 2
    const isEqual = secure.checkHashPassword(user.newPassword, db.response.m_pass)
    expect(isEqual).toEqual(true)
  })

  it('401: claims', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token + 'XXX',
      user.newPassword,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })
  
  it('404: no data', async () => {
    const res_reset_second = await seconded()
    // break
    await pool.updateOneOrThrow({ m_name: 'XXX' }, { m_name: user.name } , 'AND', 'members')
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('403: status', async () => {
    const res_reset_second = await seconded()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name } , 'AND', 'members')
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('200: hook: onTransactionLast', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice,
      {
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
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice,
      {
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
  }, 10000)

  it('204: mailFormat', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice,
      {
        mailFormat: {
          subject: 'Dear {{name}} reset verify subject',
          body: 'Dear {{name}} reset verify body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user reset verify subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user reset verify body')
  })

  it('204: sendCompleatNotice', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
  })

  it('204: Positive case', async () => {
    const res_reset_second = await seconded()
    // test
    const res1 = await plugin.resetPasswordVerify(
      res_reset_second.body.alternate_token,
      user.newPassword,
      '111.111.111.111',
      user.sessionDevice,
      {
        forceAllLogout: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(200)
    const db = await pool.select<SessionInsert>('sessions', [ 'm_ip'], { m_role: 0 })
    if (db.fail()) throw 2
    expect(db.response.rowCount).toEqual(2)
  })

})