import * as bcrypt from 'bcryptjs'

const randomNumber = (min: number, max: number): number => {
  return min + Math.floor(Math.random() * (max - (min - 1)))
}

export const createOneTimeToken = (): string => {
  return randomNumber(100000, 999999).toString()
}

export const convertOneTimeTokenToHash = (otp_hash: string, salt_rounds: number): string => {
  return bcrypt.hashSync(otp_hash, salt_rounds)
}

export const verifyOneTimeToken = (otp_hash: string, hash: string): boolean => {
  return bcrypt.compareSync(otp_hash + '', hash)
}
