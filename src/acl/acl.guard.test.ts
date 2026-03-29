import type { ExecutionContext } from '@nestjs/common'
import type { Reflector } from '@nestjs/core'
import { describe, expect, it, vi } from 'vitest'

import type { IamAclMetadata, IamProfile } from '@/iam.types.js'

import { AclGuard } from './acl.guard.js'
import type { IamAclService } from './acl.service.js'

type MockRequest = { params: { workspaceId: string }; user: IamProfile | undefined }

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
	metadata: IamAclMetadata<MockRequest> | undefined,
	profile?: IamProfile,
) {
	const request: MockRequest = {
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
		aclService: aclService as unknown as IamAclService,
		context: context as unknown as ExecutionContext,
		reflector: reflector as unknown as Reflector,
		request,
	}
}

describe('AclGuard', () => {
	it('should return true when no ACL metadata', async () => {
		const { reflector, aclService, context } = createContext(undefined)
		const guard = new AclGuard(reflector, aclService)

		const result = await guard.canActivate(context)
		expect(result).toBe(true)
	})

	it('should return false when no profile on request', async () => {
		const metadata: IamAclMetadata<MockRequest> = {
			getContext: (req) => ({
				workspaceId: req.params.workspaceId,
			}),
			permission: 'user:read',
		}
		const { reflector, aclService, context } = createContext(metadata, undefined)
		const guard = new AclGuard(reflector, aclService)

		const result = await guard.canActivate(context)
		expect(result).toBe(false)
	})

	it('should call aclService.canPerformAction and return true', async () => {
		const metadata: IamAclMetadata<MockRequest> = {
			getContext: (req) => ({
				workspaceId: req.params.workspaceId,
			}),
			permission: 'user:read',
		}
		const { reflector, aclService, context } = createContext(metadata, mockProfile)
		const guard = new AclGuard(reflector, aclService)

		const result = await guard.canActivate(context)
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
