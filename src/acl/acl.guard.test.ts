import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { IamAclMetadata, IamProfile } from '@/iam.types.js'

import { AclGuard } from './acl.guard.js'
import { AclService } from './acl.service.js'

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

function createContext(
	metadata: IamAclMetadata | undefined,
	profile?: IamProfile,
) {
	const request = {
		params: {
			workspaceId: 'ws-1',
		},
		user: profile,
	}
	const handler = () => {}

	const reflector = {
		get: vi.fn().mockReturnValue(metadata),
	}

	const aclService = {
		canPerformAction: vi.fn(),
	}

	const context = {
		getHandler: () => handler,
		switchToHttp: () => ({
			getRequest: () => request,
		}),
	}

	return {
		aclService,
		context,
		reflector,
		request,
	}
}

describe('AclGuard', () => {
	it('should return true when no ACL metadata', async () => {
		const { reflector, aclService, context } = createContext(undefined)
		const guard = new AclGuard(reflector as any, aclService as any)

		const result = await guard.canActivate(context as any)
		expect(result).toBe(true)
	})

	it('should return false when no profile on request', async () => {
		const metadata: IamAclMetadata = {
			getContext: (req: any) => ({
				workspaceId: req.params.workspaceId,
			}),
			permission: 'user:read',
		}
		const { reflector, aclService, context } = createContext(
			metadata,
			undefined,
		)
		const guard = new AclGuard(reflector as any, aclService as any)

		const result = await guard.canActivate(context as any)
		expect(result).toBe(false)
	})

	it('should call aclService.canPerformAction and return true', async () => {
		const metadata: IamAclMetadata = {
			getContext: (req: any) => ({
				workspaceId: req.params.workspaceId,
			}),
			permission: 'user:read',
		}
		const { reflector, aclService, context } = createContext(
			metadata,
			mockProfile,
		)
		const guard = new AclGuard(reflector as any, aclService as any)

		const result = await guard.canActivate(context as any)
		expect(result).toBe(true)
		expect(aclService.canPerformAction).toHaveBeenCalledWith(
			mockProfile,
			'user:read',
			{
				workspaceId: 'ws-1',
			},
		)
	})
})
