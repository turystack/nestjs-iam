import { jwtVerify } from 'jose'
import { describe, expect, it } from 'vitest'

import { issueTokens, verifyRefreshToken } from './token.js'

const SECRET = 'test-secret-key-for-jwt-signing'

describe('issueTokens', () => {
	it('should return accessToken, refreshToken, and expiresIn', async () => {
		const result = await issueTokens({ secret: SECRET }, 'user-1')

		expect(result).toHaveProperty('accessToken')
		expect(result).toHaveProperty('refreshToken')
		expect(result).toHaveProperty('expiresIn')
		expect(typeof result.accessToken).toBe('string')
		expect(typeof result.refreshToken).toBe('string')
		expect(typeof result.expiresIn).toBe('number')
	})

	it('should use default expiresIn of 15m (900s)', async () => {
		const result = await issueTokens({ secret: SECRET }, 'user-1')

		expect(result.expiresIn).toBe(900)
	})

	it('should sign accessToken with userId', async () => {
		const result = await issueTokens({ secret: SECRET }, 'user-1')
		const secretKey = new TextEncoder().encode(SECRET)
		const { payload } = await jwtVerify(result.accessToken, secretKey)

		expect(payload.userId).toBe('user-1')
		expect(payload.rt).toBeUndefined()
	})

	it('should sign refreshToken with userId and rt flag', async () => {
		const result = await issueTokens({ secret: SECRET }, 'user-1')
		const secretKey = new TextEncoder().encode(SECRET)
		const { payload } = await jwtVerify(result.refreshToken, secretKey)

		expect(payload.userId).toBe('user-1')
		expect(payload.rt).toBe(true)
	})

	it('should respect custom accessExpiresIn', async () => {
		const result = await issueTokens({ secret: SECRET, accessExpiresIn: '30m' }, 'user-1')

		expect(result.expiresIn).toBe(1800)
	})

	it('should respect custom refreshExpiresIn', async () => {
		const result = await issueTokens({ secret: SECRET, refreshExpiresIn: '14d' }, 'user-1')
		const secretKey = new TextEncoder().encode(SECRET)
		const { payload } = await jwtVerify(result.refreshToken, secretKey)

		expect(payload.exp).toBeDefined()
	})
})

describe('verifyRefreshToken', () => {
	it('should verify a valid refresh token and return userId', async () => {
		const { refreshToken } = await issueTokens({ secret: SECRET }, 'user-1')
		const result = await verifyRefreshToken(SECRET, refreshToken)

		expect(result.userId).toBe('user-1')
	})

	it('should reject an access token (no rt flag)', async () => {
		const { accessToken } = await issueTokens({ secret: SECRET }, 'user-1')

		await expect(verifyRefreshToken(SECRET, accessToken)).rejects.toThrow(
			'Invalid refresh token',
		)
	})

	it('should reject a token signed with a different secret', async () => {
		const { refreshToken } = await issueTokens({ secret: 'different-secret-key' }, 'user-1')

		await expect(verifyRefreshToken(SECRET, refreshToken)).rejects.toThrow()
	})

	it('should reject an invalid token string', async () => {
		await expect(verifyRefreshToken(SECRET, 'not-a-valid-token')).rejects.toThrow()
	})
})
