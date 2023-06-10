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

  it('204: Positive case', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
  })

  it('403: Positive case', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip,
      {
        rolePermissionLevel: 1
      }
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('204: hook: onTransactionLast', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip,
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
    expect(res1.statusCode).toEqual(204)
  })

  it('500: fail hook: onTransactionLast', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip,
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
  })

  it('400: name/mail null', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      '',
      '',
      user.ip
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(400)
  })

  it('204: Positive case', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip,
      {
        sendResetURLNotice: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
  })

  it('204: mail format', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip,
      {
        mailFormat: {
          subject: 'Dear {{name}} reset first subject',
          body: 'Dear {{name}} reset first body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user reset first subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user reset first body')
  })

  it('404: no date', async () => {
    const res1_created = await created()
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name + 'XXX',
      user.mail,
      user.ip
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(404)
  })

  it('403: status', async () => {
    const res1_created = await created()
    // brake
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.resetPasswordFirst(
      user.name,
      user.mail,
      user.ip
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

})
