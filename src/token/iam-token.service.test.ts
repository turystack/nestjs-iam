import { jwtVerify } from 'jose'
import { describe, expect, it } from 'vitest'

import type { IamOptions } from '@/iam.types.js'

import { IamTokenService } from './iam-token.service.js'

const SECRET = 'test-secret-key-for-jwt-signing'

function createService(overrides: Partial<IamOptions> = {}): IamTokenService {
	const options: IamOptions = {
		permissions: {},
		profileResolver: async () => null,
		secret: SECRET,
		...overrides,
	}

	return new IamTokenService(options)
}

describe('IamTokenService', () => {
	describe('issueTokens', () => {
		it('should return accessToken, refreshToken, and expiresIn', async () => {
			const service = createService()
			const result = await service.issueTokens('user-1')

			expect(result).toHaveProperty('accessToken')
			expect(result).toHaveProperty('refreshToken')
			expect(result).toHaveProperty('expiresIn')
			expect(typeof result.accessToken).toBe('string')
			expect(typeof result.refreshToken).toBe('string')
			expect(typeof result.expiresIn).toBe('number')
		})

		it('should use default expiresIn of 15m (900s)', async () => {
			const service = createService()
			const result = await service.issueTokens('user-1')

			expect(result.expiresIn).toBe(900)
		})

		it('should sign accessToken with userId', async () => {
			const service = createService()
			const result = await service.issueTokens('user-1')
			const secretKey = new TextEncoder().encode(SECRET)
			const { payload } = await jwtVerify(result.accessToken, secretKey)

			expect(payload.userId).toBe('user-1')
			expect(payload.rt).toBeUndefined()
		})

		it('should sign refreshToken with userId and rt flag', async () => {
			const service = createService()
			const result = await service.issueTokens('user-1')
			const secretKey = new TextEncoder().encode(SECRET)
			const { payload } = await jwtVerify(result.refreshToken, secretKey)

			expect(payload.userId).toBe('user-1')
			expect(payload.rt).toBe(true)
		})

		it('should respect custom accessExpiresIn', async () => {
			const service = createService({
				accessExpiresIn: '30m',
			})
			const result = await service.issueTokens('user-1')

			expect(result.expiresIn).toBe(1800)
		})

		it('should respect custom refreshExpiresIn', async () => {
			const service = createService({
				refreshExpiresIn: '14d',
			})
			const result = await service.issueTokens('user-1')
			const secretKey = new TextEncoder().encode(SECRET)
			const { payload } = await jwtVerify(result.refreshToken, secretKey)

			expect(payload.exp).toBeDefined()
		})
	})

	describe('verifyRefreshToken', () => {
		it('should verify a valid refresh token and return userId', async () => {
			const service = createService()
			const { refreshToken } = await service.issueTokens('user-1')
			const result = await service.verifyRefreshToken(refreshToken)

			expect(result.userId).toBe('user-1')
		})

		it('should reject an access token (no rt flag)', async () => {
			const service = createService()
			const { accessToken } = await service.issueTokens('user-1')

			await expect(service.verifyRefreshToken(accessToken)).rejects.toThrow(
				'Invalid refresh token',
			)
		})

		it('should reject a token signed with a different secret', async () => {
			const otherService = createService({
				secret: 'different-secret-key',
			})
			const { refreshToken } = await otherService.issueTokens('user-1')
			const service = createService()

			await expect(service.verifyRefreshToken(refreshToken)).rejects.toThrow()
		})

		it('should reject an invalid token string', async () => {
			const service = createService()

			await expect(
				service.verifyRefreshToken('not-a-valid-token'),
			).rejects.toThrow()
		})
	})
})
