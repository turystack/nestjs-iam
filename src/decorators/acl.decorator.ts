import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common'

import { ACL_KEY } from '@/iam.constants.js'
import type { IamAclContext, IamAclMetadata } from '@/iam.types.js'

import { AclGuard } from '@/acl/acl.guard.js'
import { AuthGuard } from '@/auth/auth.guard.js'

export const ACL = <T = {}>(
	permission: string,
	getContext: (request: T) => IamAclContext,
) =>
	applyDecorators(
		SetMetadata<string, IamAclMetadata<T>>(ACL_KEY, {
			getContext,
			permission,
		}),
		UseGuards(AuthGuard, AclGuard),
	)
