import { describe, expect, it } from 'vitest'

import { compareHash, createHash } from './crypto.js'

describe('createHash', () => {
	it('should return a bcrypt hash', async () => {
		const hash = await createHash('my-password')

		expect(hash).toBeDefined()
		expect(hash).not.toBe('my-password')
		expect(hash.startsWith('$2a$')).toBe(true)
	})

	it('should produce different hashes for the same password', async () => {
		const hash1 = await createHash('my-password')
		const hash2 = await createHash('my-password')

		expect(hash1).not.toBe(hash2)
	})
})

describe('compareHash', () => {
	it('should return true for matching password and hash', async () => {
		const hash = await createHash('my-password')
		const result = await compareHash('my-password', hash)

		expect(result).toBe(true)
	})

	it('should return false for non-matching password', async () => {
		const hash = await createHash('my-password')
		const result = await compareHash('wrong-password', hash)

		expect(result).toBe(false)
	})
})
