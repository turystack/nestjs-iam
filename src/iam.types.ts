import type { FactoryProvider, ModuleMetadata } from '@nestjs/common'
import type { ConfigService } from '@nestjs/config'

export type IamProfile = {
	userId: string
	workspaceId: string
	scopes: IamScope[]
}

export type IamScope = {
	kind: 'WORKSPACE' | 'ORGANIZATION'
	organization?: {
		organizationId: string
	}
	role?: {
		roleId: string
		name: string
	}
	permissionIds: string[]
}

export type IamPermissions = Record<string, string[]>

export type IamProfileResolver = (userId: string) => Promise<IamProfile | null>

export type IamAclContext = {
	workspaceId: string
	organizationId?: string
}

export type IamAclMetadata<T = {}> = {
	permission: string
	getContext: (request: T) => IamAclContext
}

export type IamOptions = {
	secret: string
	permissions: IamPermissions
	profileResolver: IamProfileResolver
}

export type IamModuleOptions = {
	imports?: ModuleMetadata['imports']
	inject?: FactoryProvider['inject']
	useFactory: (
		config: ConfigService,
		...args: unknown[]
	) => IamOptions | Promise<IamOptions>
}
