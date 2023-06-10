import { MailerStorage } from 'ninsho-module-mailer'
import { TestHook, TestHookFail, initializeLocalPlugin } from './x-service'

const { plugin } = initializeLocalPlugin()

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

  it('201: Positive case', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {
        view_name: user.view_name,
        tel: user.tel
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(201)
  })

  it('409: name conflict', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {}
    )
    if (res1.fail()) throw 1
    const res2 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail + 'XXX',
      user.pass,
      user.ip,
      {}
    )
    if (!!!res2.fail()) throw 2
    expect(res2.statusCode).toEqual(409)
  })

  it('409: mail conflict', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {}
    )
    if (res1.fail()) throw 1
    const res2 = await plugin.createUser2faFirst<MCustomT>(
      user.name + 'XXX',
      user.mail,
      user.pass,
      user.ip,
      {}
    )
    if (!!!res2.fail()) throw 2
    expect(res2.statusCode).toEqual(409)
  })

  it('201: hook: onTransactionLast', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {},
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
    expect(res1.statusCode).toEqual(201)
  })

  it('500: hook: onTransactionLast', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {},
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

  it('201: sendCompleatNotice', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {},
      {
        sendCompleatNotice: false
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(201)
  })

  it('201: mail format', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {},
      {
        mailFormat: {
          subject: 'Dear {{name}} create subject',
          body: 'Dear {{name}} create body'
        }
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(201)
    expect(MailerStorage[user.mail].mailSubject).toEqual('Dear test_user create subject')
    expect(MailerStorage[user.mail].mailBody).toEqual('Dear test_user create body')
  })

  it('201: mail format', async () => {
    const res1 = await plugin.createUser2faFirst<MCustomT>(
      user.name,
      user.mail,
      user.pass,
      user.ip,
      {},
      {
        role: 0
      }
    )
    if (res1.fail()) throw 1
    expect(res1.statusCode).toEqual(201)
  })

})
