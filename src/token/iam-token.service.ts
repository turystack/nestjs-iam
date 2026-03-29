import { Inject, Injectable } from '@nestjs/common'
import { jwtVerify, SignJWT } from 'jose'

import { IAM_OPTIONS } from '@/iam.constants.js'
import type { IamOptions, TokenPair } from '@/iam.types.js'

@Injectable()
export class IamTokenService {
	private readonly secretKey: Uint8Array

	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
	) {
		this.secretKey = new TextEncoder().encode(options.secret)
	}

	async issueTokens(userId: string): Promise<TokenPair> {
		const accessExpiresIn = this.options.accessExpiresIn ?? '15m'
		const refreshExpiresIn = this.options.refreshExpiresIn ?? '7d'

		const accessToken = await new SignJWT({
			userId,
		})
			.setProtectedHeader({
				alg: 'HS256',
			})
			.setIssuedAt()
			.setExpirationTime(accessExpiresIn)
			.sign(this.secretKey)

		const refreshToken = await new SignJWT({
			rt: true,
			userId,
		})
			.setProtectedHeader({
				alg: 'HS256',
			})
			.setIssuedAt()
			.setExpirationTime(refreshExpiresIn)
			.sign(this.secretKey)

		const expiresIn = this.parseExpiresIn(accessExpiresIn)

		return {
			accessToken,
			expiresIn,
			refreshToken,
		}
	}

	async verifyRefreshToken(token: string): Promise<{
		userId: string
	}> {
		const { payload } = await jwtVerify(token, this.secretKey, {
			algorithms: [
				'HS256',
			],
		})

		if (!payload.rt || typeof payload.userId !== 'string') {
			throw new Error('Invalid refresh token')
		}

		return {
			userId: payload.userId,
		}
	}

	private parseExpiresIn(value: string): number {
		const match = value.match(/^(\d+)([smhd])$/)

		if (!match) {
			return 3600
		}

		const amount = Number.parseInt(match[1], 10)
		const unit = match[2]
		const multipliers: Record<string, number> = {
			d: 86400,
			h: 3600,
			m: 60,
			s: 1,
		}

		return amount * (multipliers[unit] ?? 3600)
	}
}
