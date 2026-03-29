import bcrypt from 'bcryptjs'

const SALT_ROUNDS = 10

export async function createHash(value: string): Promise<string> {
	return bcrypt.hash(value, SALT_ROUNDS)
}

export async function compareHash(value: string, hash: string): Promise<boolean> {
	return bcrypt.compare(value, hash)
}
