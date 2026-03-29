export { IamModule } from '@/iam.module.js'
export type {
	IamAclContext,
	IamModuleOptions,
	IamOptions,
	IamPermissions,
	IamProfile,
	IamProfileResolver,
	IamScope,
	TokenPair,
} from '@/iam.types.js'

export { AclService } from '@/acl/acl.service.js'
export { ACL } from '@/decorators/acl.decorator.js'
export { Auth } from '@/decorators/auth.decorator.js'
export { Profile } from '@/decorators/authenticated-profile.decorator.js'
export { IamForbiddenException } from '@/exceptions/iam-forbidden.exception.js'
export { IamUnauthorizedException } from '@/exceptions/iam-unauthorized.exception.js'
export { compareHash, createHash } from '@/shared/crypto/index.js'
export type { TokenOptions } from '@/shared/token/index.js'
export { issueTokens, verifyRefreshToken } from '@/shared/token/index.js'
