import {
	type CanActivate,
	type ExecutionContext,
	Inject,
	Injectable,
} from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { ACL_KEY } from '@/iam.constants.js'
import type { IamAclMetadata, IamProfile } from '@/iam.types.js'

import { IamAclService } from './acl.service.js'

@Injectable()
export class AclGuard implements CanActivate {
	constructor(
		@Inject(Reflector)
		private readonly reflector: Reflector,
		@Inject(IamAclService)
		private readonly aclService: IamAclService,
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const aclMetadata = this.reflector.get<IamAclMetadata | undefined>(
			ACL_KEY,
			context.getHandler(),
		)

		if (!aclMetadata) {
			return true
		}

		const request = context.switchToHttp().getRequest()
		const profile: IamProfile = request.user

		if (!profile) {
			return false
		}

		const aclContext = aclMetadata.getContext(request)

		this.aclService.canPerformAction(
			profile,
			aclMetadata.permission,
			aclContext,
		)

		return true
	}
}
