import { beforeEach, describe, expect, it } from 'vitest'

import type { IamOptions, IamPermissions, IamProfile } from '@/iam.types.js'

import { IamAclService } from './acl.service.js'

import { IamForbiddenException } from '@/exceptions/iam-forbidden.exception.js'

const PERMISSIONS: IamPermissions = {
	billing: [
		'read',
		'update',
	],
	product: [
		'manage',
		'create',
		'read',
		'update',
		'delete',
	],
	user: [
		'create',
		'read',
		'update',
		'delete',
	],
}

function createProfile(input: {
	organizationPermissions?: string[]
	workspacePermissions?: string[]
	workspaceId?: string
}): IamProfile {
	return {
		organizationId: 'org-1',
		...(input.organizationPermissions
			? {
					organizationRole: {
						name: 'Org Role',
						permissionIds: input.organizationPermissions,
						roleId: 'role-org',
					},
				}
			: {}),
		...(input.workspacePermissions
			? {
					workspaceRole: {
						name: 'Workspace Role',
						permissionIds: input.workspacePermissions,
						roleId: 'role-ws',
						workspaceId: input.workspaceId ?? 'ws-1',
					},
				}
			: {}),
		userId: 'user-1',
	}
}

describe('IamAclService', () => {
	let service: IamAclService

	beforeEach(() => {
		const options: IamOptions = {
			permissions: PERMISSIONS,
			secret: 'test',
		}
		service = new IamAclService(options)
	})

	describe('organization role', () => {
		it('should allow when the organization role has the exact permission', () => {
			const profile = createProfile({
				organizationPermissions: [
					'billing:read',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'billing:read'),
			).not.toThrow()
		})

		it('should throw when the permission is missing', () => {
			const profile = createProfile({
				organizationPermissions: [
					'billing:read',
				],
			})

			expect(() => service.canPerformAction(profile, 'billing:update')).toThrow(
				IamForbiddenException,
			)
		})

		it('should apply organization grants in any workspace context', () => {
			const profile = createProfile({
				organizationPermissions: [
					'product:read',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'product:read', {
					workspaceId: 'ws-9',
				}),
			).not.toThrow()
		})

		it('should let organization:manage do everything, in any context', () => {
			const profile = createProfile({
				organizationPermissions: [
					'organization:manage',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'billing:update'),
			).not.toThrow()
			expect(() =>
				service.canPerformAction(profile, 'product:delete', {
					workspaceId: 'ws-2',
				}),
			).not.toThrow()
		})

		it('should expand subject:manage into the catalog actions', () => {
			const profile = createProfile({
				organizationPermissions: [
					'product:manage',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'product:read'),
			).not.toThrow()
			expect(() =>
				service.canPerformAction(profile, 'product:delete'),
			).not.toThrow()
		})

		it('should deny a mismatched organization context', () => {
			const profile = createProfile({
				organizationPermissions: [
					'billing:read',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'billing:read', {
					organizationId: 'org-other',
				}),
			).toThrow(IamForbiddenException)
		})
	})

	describe('workspace role', () => {
		it('should allow in the workspace the role belongs to', () => {
			const profile = createProfile({
				workspaceId: 'ws-1',
				workspacePermissions: [
					'product:create',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'product:create', {
					workspaceId: 'ws-1',
				}),
			).not.toThrow()
		})

		it('should deny in another workspace', () => {
			const profile = createProfile({
				workspaceId: 'ws-1',
				workspacePermissions: [
					'product:create',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'product:create', {
					workspaceId: 'ws-2',
				}),
			).toThrow(IamForbiddenException)
		})

		it('should not leak workspace grants into organization-level checks', () => {
			const profile = createProfile({
				workspaceId: 'ws-1',
				workspacePermissions: [
					'billing:read',
				],
			})

			expect(() => service.canPerformAction(profile, 'billing:read')).toThrow(
				IamForbiddenException,
			)
		})

		it('should let workspace:manage do everything within its workspace only', () => {
			const profile = createProfile({
				workspaceId: 'ws-1',
				workspacePermissions: [
					'workspace:manage',
				],
			})

			expect(() =>
				service.canPerformAction(profile, 'product:delete', {
					workspaceId: 'ws-1',
				}),
			).not.toThrow()
			expect(() =>
				service.canPerformAction(profile, 'product:delete', {
					workspaceId: 'ws-2',
				}),
			).toThrow(IamForbiddenException)
			expect(() => service.canPerformAction(profile, 'billing:update')).toThrow(
				IamForbiddenException,
			)
		})
	})

	describe('union of roles', () => {
		it('should combine organization and workspace grants', () => {
			const profile = createProfile({
				organizationPermissions: [
					'billing:read',
				],
				workspaceId: 'ws-1',
				workspacePermissions: [
					'product:create',
				],
			})

			// organization grant works on an organization-level check
			expect(() =>
				service.canPerformAction(profile, 'billing:read'),
			).not.toThrow()
			// workspace grant works in its workspace
			expect(() =>
				service.canPerformAction(profile, 'product:create', {
					workspaceId: 'ws-1',
				}),
			).not.toThrow()
			// neither grants the other's scope
			expect(() => service.canPerformAction(profile, 'product:create')).toThrow(
				IamForbiddenException,
			)
		})
	})

	describe('no roles', () => {
		it('should deny a user with no roles', () => {
			const profile = createProfile({})

			expect(() => service.canPerformAction(profile, 'user:read')).toThrow(
				IamForbiddenException,
			)
		})
	})
})
