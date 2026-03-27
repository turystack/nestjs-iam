import type { ExecutionContext } from '@nestjs/common'
import { SignJWT } from 'jose'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { IamOptions, IamProfile } from '@/iam.types.js'

import { AuthGuard } from './auth.guard.js'

import { IamUnauthorizedException } from '@/exceptions/iam-unauthorized.exception.js'

const SECRET = 'test-secret-key-for-jwt-signing'

const mockProfile: IamProfile = {
	scopes: [
		{
			kind: 'WORKSPACE',
			permissionIds: [
				'user:read',
			],
		},
	],
	userId: 'user-1',
	workspaceId: 'ws-1',
}

async function createToken(payload: Record<string, unknown>, secret = SECRET) {
	const secretKey = new TextEncoder().encode(secret)
	return new SignJWT(payload)
		.setProtectedHeader({
			alg: 'HS256',
		})
		.setIssuedAt()
		.sign(secretKey)
}

function createContext(headers: Record<string, string> = {}) {
	const request = {
		headers,
		user: undefined as IamProfile | undefined,
	}
	const context = {
		request,
		switchToHttp: () => ({
			getRequest: () => request,
		}),
	}
	return context as unknown as ExecutionContext & { request: typeof request }
}

describe('AuthGuard', () => {
	let guard: AuthGuard
	let profileResolver: ReturnType<typeof vi.fn>
	let options: IamOptions

	beforeEach(() => {
		profileResolver = vi.fn().mockResolvedValue(mockProfile)
		options = {
			permissions: {},
			profileResolver,
			secret: SECRET,
		}
		guard = new AuthGuard(options)
	})

	it('should throw IamUnauthorizedException when no authorization header', async () => {
		const ctx = createContext()
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			IamUnauthorizedException,
		)
	})

	it('should throw IamUnauthorizedException when token is empty', async () => {
		const ctx = createContext({
			authorization: 'Bearer ',
		})
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			IamUnauthorizedException,
		)
	})

	it('should throw IamUnauthorizedException when token is invalid', async () => {
		const ctx = createContext({
			authorization: 'Bearer invalid-token',
		})
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			IamUnauthorizedException,
		)
	})

	it('should throw IamUnauthorizedException when token has no userId', async () => {
		const token = await createToken({
			sub: 'no-userId-field',
		})
		const ctx = createContext({
			authorization: `Bearer ${token}`,
		})
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			IamUnauthorizedException,
		)
	})

	it('should throw IamUnauthorizedException when profileResolver returns null', async () => {
		profileResolver.mockResolvedValue(null)
		const token = await createToken({
			userId: 'user-1',
		})
		const ctx = createContext({
			authorization: `Bearer ${token}`,
		})
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			IamUnauthorizedException,
		)
	})

	it('should set request.user and return true on valid token', async () => {
		const token = await createToken({
			userId: 'user-1',
		})
		const ctx = createContext({
			authorization: `Bearer ${token}`,
		})
		const result = await guard.canActivate(ctx)

		expect(result).toBe(true)
		expect(ctx.request.user).toEqual(mockProfile)
		expect(profileResolver).toHaveBeenCalledWith('user-1')
	})
})
