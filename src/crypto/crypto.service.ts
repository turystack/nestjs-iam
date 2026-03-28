import bcrypt from 'bcryptjs'
import { Injectable } from '@nestjs/common'

const SALT_ROUNDS = 10

@Injectable()
export class IamCryptoService {
	async hashPassword(password: string): Promise<string> {
		return bcrypt.hash(password, SALT_ROUNDS)
	}

	async comparePassword(password: string, hash: string): Promise<boolean> {
		return bcrypt.compare(password, hash)
	}
}
