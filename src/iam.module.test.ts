import type { ClassProvider, Provider } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import { ConfigModule } from '@turystack/nestjs-config'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { z } from 'zod'

import { IAM_OPTIONS, IAM_PROFILE_RESOLVER } from '@/iam.constants.js'
import { IamModule } from '@/iam.module.js'
import type { IamProfileResolver } from '@/iam.types.js'

import { AclGuard } from '@/acl/acl.guard.js'
import { IamAclService } from '@/acl/acl.service.js'
import { AuthGuard } from '@/auth/auth.guard.js'
import { IamTokenService } from '@/token/index.js'

class FakeProfileService implements IamProfileResolver {
	async resolveProfile() {
		return null
	}
}

const findProvider = (providers: Provider[], token: unknown) =>
	providers.find(
		(provider) =>
			typeof provider === 'object' &&
			'provide' in provider &&
			provider.provide === token,
	)

describe('IamModule', () => {
	describe('register', () => {
		afterEach(() => {
			vi.unstubAllEnvs()
		})

		it('should expose guards and services globally', () => {
			const dynamicModule = IamModule.register({
				permissions: {
					user: [
						'read',
					],
				},
				profileResolver: FakeProfileService,
				secret: 'test-secret',
			})

			expect(dynamicModule.module).toBe(IamModule)
			expect(dynamicModule.global).toBe(true)
			expect(dynamicModule.imports).toEqual([])
			expect(dynamicModule.exports).toEqual([
				IAM_OPTIONS,
				AuthGuard,
				AclGuard,
				IamAclService,
				IamTokenService,
			])
		})

		it('should strip the resolver and imports out of the options value', async () => {
			const moduleRef = await Test.createTestingModule({
				imports: [
					IamModule.register({
						accessExpiresIn: '30m',
						permissions: {},
						profileResolver: FakeProfileService,
						secret: 'test-secret',
					}),
				],
			}).compile()

			expect(moduleRef.get(IAM_OPTIONS)).toEqual({
				accessExpiresIn: '30m',
				permissions: {},
				secret: 'test-secret',
			})
		})

		it('should bind the resolver class to the resolver token', () => {
			const dynamicModule = IamModule.register({
				permissions: {},
				profileResolver: FakeProfileService,
				secret: 'test-secret',
			})

			const resolverProvider = findProvider(
				dynamicModule.providers ?? [],
				IAM_PROFILE_RESOLVER,
			) as ClassProvider
			expect(resolverProvider.useClass).toBe(FakeProfileService)
		})

		it('should forward imports for the resolver dependencies', () => {
			class UserLibModule {}

			const dynamicModule = IamModule.register({
				imports: [
					UserLibModule,
				],
				permissions: {},
				profileResolver: FakeProfileService,
				secret: 'test-secret',
			})

			expect(dynamicModule.imports).toEqual([
				UserLibModule,
			])
		})

		it('should resolve options from a config factory', async () => {
			vi.stubEnv('JWT_SECRET', 'factory-secret')

			const moduleRef = await Test.createTestingModule({
				imports: [
					ConfigModule.register({
						envFilePath: false,
						schema: {
							JWT_SECRET: z.string(),
						},
					}),
					IamModule.register((config) => ({
						permissions: {
							user: [
								'read',
							],
						},
						profileResolver: FakeProfileService,
						secret: config.get('JWT_SECRET') as string,
					})),
				],
			}).compile()

			expect(moduleRef.get(IAM_OPTIONS)).toEqual({
				permissions: {
					user: [
						'read',
					],
				},
				secret: 'factory-secret',
			})
			expect(moduleRef.get(IAM_PROFILE_RESOLVER)).toBeInstanceOf(
				FakeProfileService,
			)
		})

		it('should reject a config factory without ConfigModule', async () => {
			await expect(
				Test.createTestingModule({
					imports: [
						IamModule.register((config) => ({
							permissions: {},
							profileResolver: FakeProfileService,
							secret: config.get('JWT_SECRET') as string,
						})),
					],
				}).compile(),
			).rejects.toThrow(
				'requires ConfigModule (@turystack/nestjs-config) to be registered',
			)
		})
	})
})
