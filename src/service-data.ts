import { SessionInsert, IPoolClient, E401, E404, E500, IResult, Success } from 'ninsho-base'
import { getNowUnixTime } from 'ninsho-utils'

import { LendOfHere } from './plugin-standard-2fa-api'

export async function upsertSessionRowWithReturnedSessionToken(
  lend: LendOfHere,
  members_id: number,
  role: number,
  name: string,
  ip: string,
  sessionDevice: string,
  connection?: IPoolClient
): Promise<IResult<{
  sessionToken: string,
}, E500 | E401 | E404>> {

  const { sessionToken, hashToken } = lend.modules.secure.createSessionTokenWithHash()

  const resUpsert = await lend.modules.pool.upsertSessionRecord<SessionInsert>(
    {
      members_id,
      m_name: name,
      m_ip: ip,
      m_device: sessionDevice,
      m_role: role,
      token: hashToken,
      created_time: getNowUnixTime()
    },
    [
      'm_name',
      'm_ip',
      'm_device'
    ],
    [
      'token'
    ],
    lend.options.tableName.sessions,
    connection
  )
  /* istanbul ignore if */
  if (resUpsert.fail()) return resUpsert.pushReplyCode(2399)

  return new Success(
    {
      sessionToken
    }
  )
}