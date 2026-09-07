import type { ModuleMetadata, Type } from '@nestjs/common'

export type IamRole = {
	roleId: string
	name: string
	permissionIds: string[]
}

export type IamWorkspaceRole = IamRole & {
	workspaceId: string
}

/**
 * One central organization, N workspaces. Tokens are minted for at most one
 * workspace, so the profile carries at most one role of each kind:
 * - `organizationRole` — the user's role in the organization as a whole
 * - `workspaceRole` — the user's role in the workspace the token was minted for
 *
 * Both are optional: an organization-only user has no `workspaceRole`; a
 * workspace-only user has no `organizationRole`.
 */
export type IamProfile = {
	userId: string
	organizationId: string
	organizationRole?: IamRole
	workspaceRole?: IamWorkspaceRole
}

export type IamPermissions = Record<string, string[]>

/**
 * The single bridge between IAM and your project: implement it in a
 * project-level ProfileResolverService (typically backed by a domain package's
 * repository) and pass the class to `IamModule.register`.
 *
 * `workspaceId` is the workspace the token was minted for (absent on
 * organization-only tokens) — return the user's role for that workspace.
 */
export interface IamProfileResolver {
	resolveProfile(
		userId: string,
		workspaceId?: string,
	): Promise<IamProfile | null>
}

/**
 * Optional cross-check data extracted from the request. Anything provided is
 * matched against the ability conditions: a mismatched `organizationId` or
 * `workspaceId` fails the permission check.
 */
export type IamAclContext = {
	organizationId?: string
	workspaceId?: string
}

export type IamAclMetadata<T = {}> = {
	permission: string
	/** Optional — organization-level routes usually need no request context. */
	getContext?: (request: T) => IamAclContext
}

export type TokenPair = {
	accessToken: string
	refreshToken: string
	expiresIn: number
}

/**
 * Where the guard looks for the access token.
 *
 * - `header` — `Authorization: Bearer <token>`. The default, and what a native
 *   or server-to-server client sends.
 * - `cookie` — an httpOnly cookie. A browser session stored this way cannot be
 *   read by a script on the page, so XSS reaches no credential.
 * - `both` — the header first, then the cookie. One API serving a web app and a
 *   mobile app needs this; an explicit bearer wins over an ambient cookie.
 */
export type IamTokenSource = 'both' | 'cookie' | 'header'

export type IamOptions = {
	secret: string
	permissions: IamPermissions
	accessExpiresIn?: string
	refreshExpiresIn?: string
	/** Default `header`, so an existing application keeps its behaviour. */
	tokenSource?: IamTokenSource
	/** Name of the cookie carrying the access token. Default `session`. */
	cookieName?: string
}

export type IamModuleOptions = IamOptions & {
	/**
	 * Class implementing {@link IamProfileResolver}. Instantiated by the
	 * module via DI — its dependencies come from global lib modules or from
	 * `imports`.
	 */
	profileResolver: Type<IamProfileResolver>
	/** Modules providing the resolver's dependencies, when they are not global. */
	imports?: ModuleMetadata['imports']
}

/**
 * Options returned by the `register((config) => ...)` factory form. `imports`
 * is excluded: the module structure is built before the `ConfigService`
 * exists, so in the factory form the resolver's dependencies must come from
 * global modules.
 */
export type IamModuleFactoryOptions = Omit<IamModuleOptions, 'imports'>
