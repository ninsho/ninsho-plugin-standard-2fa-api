import { MStatus, MemberInsert } from 'ninsho-base'
import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

const { pool, plugin } = initializeLocalPlugin()

describe('st-delete-verify', () => {

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

  let session_token = ''

  const deleteFirst = async () => {
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
    const res_delete_first = await plugin.deleteUser2faFirst(
      res_verify.body.session_token,
      user.ip,
      user.sessionDevice
    )
    if (res_delete_first.fail()) throw 300
    return res_delete_first
  }

  // =====
  // ===== test
  // =====

  it('200: Positive case', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
  })

  it('401: jwt', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token + 'XXX',
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })


  it('401: jwt', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token + 'XXX',
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })


  it('204: hook: beforePasswordCheck', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
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
    expect(res1.statusCode).toEqual(204)
  })

  it('500: fail hook: beforePasswordCheck', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
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

  it('204: hook: onTransactionLast', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
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
    expect(res1.statusCode).toEqual(204)
  })

  it('500: fail hook: onTransactionLast', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
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

  it('401: no session', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice + 'XXX'
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('403: status', async () => {
    const res1_delete = await deleteFirst()
    // brake
    await pool.updateOneOrThrow<MemberInsert>({ m_status: 9 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(403)
  })

  it('401: version', async () => {
    const res1_delete = await deleteFirst()
    // brake
    await pool.updateOneOrThrow<MemberInsert>({ version: 999 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('204: physical_deletion', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        physical_deletion: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
    // expect
    const db = await pool.selectOneOrThrow<MemberInsert>('members', '*', { m_status: MStatus.INACTIVE }, 'AND')
    if (db.fail()) throw 2
    expect(!!db.response?.m_name.match(new RegExp('^\\d+#' + user.name + '$'))).toEqual(true)
    // expect
    const diff_updated_at = new Date().getTime() - (new Date(db.response.updated_at)).getTime()
    expect(diff_updated_at < 500).toEqual(true)
  }, 7777)

  it('204: overwritePossibleOnLogicallyDeletedData', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        physical_deletion: false,
        overwritePossibleOnLogicallyDeletedData: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
    // expect
    const db = await pool.selectOneOrThrow<MemberInsert>('members', '*', { m_status: MStatus.INACTIVE }, 'AND')
    if (db.fail()) throw 2
    expect(db.response?.m_name === user.name).toEqual(true)
  })

  it('204: options', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        sendCompleatNotice: false,
        forceAllLogout: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
  })


  it('204: mail format', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice,
      {
        mailFormat: {
          subject: 'Dear {{name}} delete verify subject',
          body: 'Dear {{name}} delete verify body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(204)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user delete verify subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user delete verify body')
  })

  it('401: otp', async () => {
    const res1_delete = await deleteFirst()
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password + 'XXX',
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) throw 1
    expect(res1.statusCode).toEqual(401)
  })

  it('401: otp null', async () => {
    const res1_delete = await deleteFirst()
    // break
    await pool.updateOneOrThrow<MemberInsert>({ otp_hash: null, version: 1 }, { m_name: user.name }, 'AND', 'members')
    // test
    const res1 = await plugin.deleteUser2faVerify(
      res1_delete.system.one_time_password,
      res1_delete.body.alternate_token,
      session_token,
      user.ip,
      user.sessionDevice
    )
    if (!!!res1.fail()) { console.log(res1.body); throw 1 }
    expect(res1.statusCode).toEqual(500)
    expect(res1.body.replyCode).toEqual([ 2344 ])
  })

})
