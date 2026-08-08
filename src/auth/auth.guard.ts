import {
	type CanActivate,
	type ExecutionContext,
	Inject,
	Injectable,
} from '@nestjs/common'
import { jwtVerify } from 'jose'

import { IAM_OPTIONS, IAM_PROFILE_RESOLVER } from '@/iam.constants.js'
import { publishProfileToContext } from '@/iam.context.js'
import type { IamOptions, IamProfileResolver } from '@/iam.types.js'

import { IamUnauthorizedException } from '@/exceptions/iam-unauthorized.exception.js'

@Injectable()
export class AuthGuard implements CanActivate {
	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
		@Inject(IAM_PROFILE_RESOLVER)
		private readonly profileResolver: IamProfileResolver,
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest()
		const authorization = request.headers.authorization

		if (!authorization) {
			throw new IamUnauthorizedException()
		}

		const [accessToken] = authorization.split(' ').reverse()

		if (!accessToken) {
			throw new IamUnauthorizedException()
		}

		try {
			const secretKey = new TextEncoder().encode(this.options.secret)

			const { payload } = await jwtVerify(accessToken, secretKey, {
				algorithms: [
					'HS256',
				],
			})

			const decoded = payload as {
				userId: string
				workspaceId?: string
			}

			if (!decoded?.userId) {
				throw new IamUnauthorizedException()
			}

			const profile = await this.profileResolver.resolveProfile(
				decoded.userId,
				decoded.workspaceId,
			)

			if (!profile) {
				throw new IamUnauthorizedException()
			}

			request.user = profile

			// Also published to the operation's context, so logs, audit columns
			// and traces see the actor without any of them being handed it.
			await publishProfileToContext(profile)

			return true
		} catch (error) {
			if (error instanceof IamUnauthorizedException) {
				throw error
			}

			throw new IamUnauthorizedException()
		}
	}
}
