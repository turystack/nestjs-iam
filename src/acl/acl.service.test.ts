import { beforeEach, describe, expect, it } from 'vitest'

import type { IamOptions, IamPermissions, IamProfile } from '@/iam.types.js'

import { IamAclService } from './acl.service.js'

import { IamForbiddenException } from '@/exceptions/iam-forbidden.exception.js'

const PERMISSIONS: IamPermissions = {
	organization: ['manage', 'create', 'read', 'update', 'delete'],
	user: ['create', 'read', 'update', 'delete'],
	workspace: ['manage', 'read'],
}

function createProfile(permissionIds: string[]): IamProfile {
	return {
		scopes: [
			{
				kind: 'WORKSPACE',
				permissionIds,
			},
		],
		userId: 'user-1',
		workspaceId: 'ws-1',
	}
}

function createProfileWithOrgScope(
	workspacePermissions: string[],
	orgPermissions: string[],
	organizationId: string,
): IamProfile {
	return {
		scopes: [
			{
				kind: 'WORKSPACE',
				permissionIds: workspacePermissions,
			},
			{
				kind: 'ORGANIZATION',
				organization: {
					organizationId,
				},
				permissionIds: orgPermissions,
			},
		],
		userId: 'user-1',
		workspaceId: 'ws-1',
	}
}

describe('IamAclService', () => {
	let service: IamAclService

	beforeEach(() => {
		const options: IamOptions = {
			permissions: PERMISSIONS,
			profileResolver: async () => null,
			secret: 'test',
		}
		service = new IamAclService(options)
	})

	it('should allow when user has the exact permission', () => {
		const profile = createProfile([
			'user:read',
		])

		expect(() =>
			service.canPerformAction(profile, 'user:read', {
				workspaceId: 'ws-1',
			}),
		).not.toThrow()
	})

	it('should throw IamForbiddenException when user lacks permission', () => {
		const profile = createProfile([
			'user:read',
		])

		expect(() =>
			service.canPerformAction(profile, 'user:create', {
				workspaceId: 'ws-1',
			}),
		).toThrow(IamForbiddenException)
	})

	it('should allow workspace:manage to access any permission', () => {
		const profile = createProfile([
			'workspace:manage',
		])

		expect(() =>
			service.canPerformAction(profile, 'user:delete', {
				workspaceId: 'ws-1',
			}),
		).not.toThrow()
	})

	it('should expand subject:manage to all non-manage actions', () => {
		const profile = createProfile([
			'organization:manage',
		])

		expect(() =>
			service.canPerformAction(profile, 'organization:read', {
				workspaceId: 'ws-1',
			}),
		).not.toThrow()

		expect(() =>
			service.canPerformAction(profile, 'organization:create', {
				workspaceId: 'ws-1',
			}),
		).not.toThrow()

		expect(() =>
			service.canPerformAction(profile, 'organization:delete', {
				workspaceId: 'ws-1',
			}),
		).not.toThrow()
	})

	it('should deny access to wrong workspace', () => {
		const profile = createProfile([
			'user:read',
		])

		expect(() =>
			service.canPerformAction(profile, 'user:read', {
				workspaceId: 'ws-other',
			}),
		).toThrow(IamForbiddenException)
	})

	it('should allow organization:manage when checking org-scoped permission', () => {
		const profile = createProfileWithOrgScope(
			[
				'organization:manage',
			],
			[
				'organization:manage',
			],
			'org-1',
		)

		expect(() =>
			service.canPerformAction(profile, 'organization:read', {
				organizationId: 'org-1',
				workspaceId: 'ws-1',
			}),
		).not.toThrow()
	})

	it('should deny when no scopes match', () => {
		const profile = createProfile([])

		expect(() =>
			service.canPerformAction(profile, 'user:read', {
				workspaceId: 'ws-1',
			}),
		).toThrow(IamForbiddenException)
	})

	it('should work without resource (no subject factory)', () => {
		const profile = createProfile([
			'user:read',
		])

		expect(() => service.canPerformAction(profile, 'user:read')).not.toThrow()
	})
})
