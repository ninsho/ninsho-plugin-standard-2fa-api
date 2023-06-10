import * as jwt from 'jsonwebtoken'

export type jwtClaim = {
  exp: number,
  m_name: string,
  m_mail: string,
  m_role: number,
  JWTSection: any,
  version: number
}

export const JWTSign = (
  name: string,
  mail: string,
  section: any,
  version: any | null,
  expSec: number,
  role: number,
  secretKey: string,
) => {

  return jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + expSec,
      m_name: name,
      m_mail: mail,
      m_role: role,
      JWTSection: section,
      version: version
    },
    secretKey
  )

}

export const JWTVerify = <jwtClaim>(
  token: string,
  section: any,
  secretKey: string,
) => {
  const claims = jwt.verify(token, secretKey) as any
  if (claims.JWTSection !== section) {
    throw new Error('process mismatch.')
  }
  return claims as jwtClaim
}
