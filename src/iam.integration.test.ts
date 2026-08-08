import { Injectable, Module } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import { describe, expect, it } from 'vitest'

import { IAM_PROFILE_RESOLVER } from '@/iam.constants.js'
import { IamModule } from '@/iam.module.js'
import type { IamProfile, IamProfileResolver } from '@/iam.types.js'

import { IamAclService } from '@/acl/acl.service.js'
import { IamTokenService } from '@/token/index.js'

const profile: IamProfile = {
	organizationId: 'org-1',
	organizationRole: {
		name: 'Admin',
		permissionIds: [
			'user:read',
		],
		roleId: 'role-1',
	},
	userId: 'u1',
}

// the lib layer (e.g. libs/user)
type User = {
	id: string
	organizationId: string
	permissionIds: string[]
}

@Injectable()
class UserRepository {
	async findById(id: string): Promise<User> {
		return {
			id,
			organizationId: 'org-1',
			permissionIds: [
				'user:read',
			],
		}
	}
}

@Module({
	exports: [
		UserRepository,
	],
	providers: [
		UserRepository,
	],
})
class UserLibModule {}

// the project-level resolver — the single bridge between IAM and the libs
@Injectable()
class ProfileResolverService implements IamProfileResolver {
	constructor(private readonly userRepository: UserRepository) {}

	async resolveProfile(userId: string): Promise<IamProfile | null> {
		const user = await this.userRepository.findById(userId)
		return user ? this.toProfile(user) : null
	}

	private toProfile(user: User): IamProfile {
		return {
			organizationId: user.organizationId,
			organizationRole: {
				name: 'Admin',
				permissionIds: user.permissionIds,
				roleId: 'role-1',
			},
			userId: user.id,
		}
	}
}

@Injectable()
class DomainService {
	constructor(
		public readonly tokenService: IamTokenService,
		public readonly aclService: IamAclService,
	) {}
}

@Module({
	providers: [
		DomainService,
	],
})
class DomainLibModule {}

describe('IamModule (integration)', () => {
	it('should wire the resolver through DI and share services app-wide', async () => {
		const moduleRef = await Test.createTestingModule({
			imports: [
				IamModule.register({
					imports: [
						UserLibModule,
					],
					permissions: {
						user: [
							'read',
							'write',
						],
					},
					profileResolver: ProfileResolverService,
					secret: 'integration-secret',
				}),
				DomainLibModule,
			],
		}).compile()

		// the resolver class was instantiated by DI, with the lib dependency injected
		const resolver = moduleRef.get<IamProfileResolver>(IAM_PROFILE_RESOLVER)
		expect(resolver).toBeInstanceOf(ProfileResolverService)
		await expect(resolver.resolveProfile('u1')).resolves.toEqual(profile)

		// domain libs share the app-wide singletons
		const domainService = moduleRef.get(DomainService)
		expect(domainService.aclService).toBeInstanceOf(IamAclService)
		expect(domainService.tokenService).toBe(moduleRef.get(IamTokenService))

		// real token round-trip — tokens are minted for one workspace
		const tokens = await domainService.tokenService.issueTokens('u1', {
			workspaceId: 'ws-1',
		})
		const verified = await domainService.tokenService.verifyRefreshToken(
			tokens.refreshToken,
		)
		expect(verified).toEqual({
			userId: 'u1',
			workspaceId: 'ws-1',
		})

		// acl works against the registered permission catalog
		expect(() =>
			domainService.aclService.canPerformAction(profile, 'user:read', {
				organizationId: 'org-1',
			}),
		).not.toThrow()
	})
})
