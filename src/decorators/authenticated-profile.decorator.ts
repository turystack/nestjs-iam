import { createParamDecorator, type ExecutionContext } from '@nestjs/common'

export const Profile = createParamDecorator(
	(_: unknown, context: ExecutionContext) => {
		const request = context.switchToHttp().getRequest()
		return request.user
	},
)
