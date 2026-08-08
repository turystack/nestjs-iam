import { createParamDecorator, type ExecutionContext } from '@nestjs/common'

/** Factory behind `@AuthenticatedProfile` — exported for testing. */
export const profileFactory = (_: unknown, context: ExecutionContext) => {
	const request = context.switchToHttp().getRequest()
	return request.user
}

/** Injects the authenticated {@link IamProfile} (set by AuthGuard) into the handler. */
export const AuthenticatedProfile = createParamDecorator(profileFactory)

/** @deprecated alias — use {@link AuthenticatedProfile}. */
export const Profile = AuthenticatedProfile
