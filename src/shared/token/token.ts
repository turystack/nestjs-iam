import { SignJWT, jwtVerify } from 'jose'

import type { TokenPair } from '@/iam.types.js'

export type TokenOptions = {
	secret: string
	accessExpiresIn?: string
	refreshExpiresIn?: string
}

export async function issueTokens(options: TokenOptions, userId: string): Promise<TokenPair> {
	const secretKey = new TextEncoder().encode(options.secret)
	const accessExpiresIn = options.accessExpiresIn ?? '15m'
	const refreshExpiresIn = options.refreshExpiresIn ?? '7d'

	const accessToken = await new SignJWT({ userId })
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setExpirationTime(accessExpiresIn)
		.sign(secretKey)

	const refreshToken = await new SignJWT({ userId, rt: true })
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setExpirationTime(refreshExpiresIn)
		.sign(secretKey)

	const expiresIn = parseExpiresIn(accessExpiresIn)

	return { accessToken, refreshToken, expiresIn }
}

export async function verifyRefreshToken(secret: string, token: string): Promise<{ userId: string }> {
	const secretKey = new TextEncoder().encode(secret)
	const { payload } = await jwtVerify(token, secretKey, {
		algorithms: ['HS256'],
	})

	if (!payload.rt || typeof payload.userId !== 'string') {
		throw new Error('Invalid refresh token')
	}

	return { userId: payload.userId }
}

function parseExpiresIn(value: string): number {
	const match = value.match(/^(\d+)([smhd])$/)

	if (!match) {
		return 3600
	}

	const amount = Number.parseInt(match[1], 10)
	const unit = match[2]
	const multipliers: Record<string, number> = {
		s: 1,
		m: 60,
		h: 3600,
		d: 86400,
	}

	return amount * (multipliers[unit] ?? 3600)
}
