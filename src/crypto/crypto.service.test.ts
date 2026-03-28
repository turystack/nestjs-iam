import { describe, expect, it } from 'vitest'

import { IamCryptoService } from './crypto.service.js'

describe('IamCryptoService', () => {
	const service = new IamCryptoService()

	describe('hashPassword', () => {
		it('should return a bcrypt hash', async () => {
			const hash = await service.hashPassword('my-password')

			expect(hash).toBeDefined()
			expect(hash).not.toBe('my-password')
			expect(hash.startsWith('$2a$')).toBe(true)
		})

		it('should produce different hashes for the same password', async () => {
			const hash1 = await service.hashPassword('my-password')
			const hash2 = await service.hashPassword('my-password')

			expect(hash1).not.toBe(hash2)
		})
	})

	describe('comparePassword', () => {
		it('should return true for matching password and hash', async () => {
			const hash = await service.hashPassword('my-password')
			const result = await service.comparePassword('my-password', hash)

			expect(result).toBe(true)
		})

		it('should return false for non-matching password', async () => {
			const hash = await service.hashPassword('my-password')
			const result = await service.comparePassword('wrong-password', hash)

			expect(result).toBe(false)
		})
	})
})
