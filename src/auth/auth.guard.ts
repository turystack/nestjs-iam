import {
	type CanActivate,
	type ExecutionContext,
	Inject,
	Injectable,
} from '@nestjs/common'
import { jwtVerify } from 'jose'

import { IAM_OPTIONS } from '@/iam.constants.js'
import type { IamOptions } from '@/iam.types.js'

import { IamUnauthorizedException } from '@/exceptions/iam-unauthorized.exception.js'

@Injectable()
export class AuthGuard implements CanActivate {
	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
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
			}

			if (!decoded?.userId) {
				throw new IamUnauthorizedException()
			}

			const profile = await this.options.profileResolver(decoded.userId)

			if (!profile) {
				throw new IamUnauthorizedException()
			}

			request.user = profile
			return true
		} catch (error) {
			if (error instanceof IamUnauthorizedException) {
				throw error
			}

			throw new IamUnauthorizedException()
		}
	}
}
