import { type DynamicModule, Module, type Provider } from '@nestjs/common'
import { ModuleRef } from '@nestjs/core'
import { ConfigService } from '@turystack/nestjs-config'

import { IAM_OPTIONS, IAM_PROFILE_RESOLVER } from '@/iam.constants.js'
import type {
	IamModuleFactoryOptions,
	IamModuleOptions,
	IamOptions,
} from '@/iam.types.js'

import { AclGuard } from '@/acl/acl.guard.js'
import { IamAclService } from '@/acl/acl.service.js'
import { AuthGuard } from '@/auth/auth.guard.js'
import { IamTokenService } from '@/token/index.js'

/** Internal token holding the register options, resolved exactly once. */
const IAM_RESOLVED_OPTIONS = Symbol('IAM_RESOLVED_OPTIONS')

@Module({})
export class IamModule {
	/**
	 * Registers the IAM globally — once, in the API root. The only bridge to
	 * your project is `profileResolver`: a class implementing
	 * `IamProfileResolver` (typically a project-level ProfileResolverService backed by
	 * a lib UserRepository/UserService). It is instantiated via DI, so its
	 * dependencies come from global lib modules or from `imports`.
	 *
	 * The `(config) => options` factory form injects the `ConfigService` from
	 * `@turystack/nestjs-config` at boot. `imports` is only accepted in the plain form:
	 * the module structure is built before the `ConfigService` exists, so in
	 * the factory form the resolver's dependencies must come from global
	 * modules.
	 */
	static register(
		options:
			| IamModuleOptions
			| ((config: ConfigService) => IamModuleFactoryOptions),
	): DynamicModule {
		return {
			exports: [
				IAM_OPTIONS,
				AuthGuard,
				AclGuard,
				IamAclService,
				IamTokenService,
			],
			global: true,
			imports: typeof options === 'function' ? [] : (options.imports ?? []),
			module: IamModule,
			providers: IamModule._resolveProviders(options),
		}
	}

	private static _resolveOptions(
		optionsOrFactory:
			| IamModuleOptions
			| ((config: ConfigService) => IamModuleFactoryOptions),
		config?: ConfigService,
	): IamModuleFactoryOptions {
		if (typeof optionsOrFactory !== 'function') {
			return optionsOrFactory
		}

		if (!config) {
			throw new Error(
				'[IamModule] register((config) => ...) requires ConfigModule (@turystack/nestjs-config) to be registered',
			)
		}

		return optionsOrFactory(config)
	}

	private static _resolveProviders(
		optionsOrFactory:
			| IamModuleOptions
			| ((config: ConfigService) => IamModuleFactoryOptions),
	): Provider[] {
		// The resolver binding is structural: in the plain form the class is
		// known at register time and bound via `useClass`, so `imports` can
		// provide its dependencies. In the factory form the class only exists
		// after the options resolve, so it is created through the module's
		// injector (global dependencies only).
		const profileResolverProvider: Provider =
			typeof optionsOrFactory === 'function'
				? {
						inject: [
							IAM_RESOLVED_OPTIONS,
							ModuleRef,
						],
						provide: IAM_PROFILE_RESOLVER,
						useFactory: (
							options: IamModuleFactoryOptions,
							moduleRef: ModuleRef,
						) => moduleRef.create(options.profileResolver),
					}
				: {
						provide: IAM_PROFILE_RESOLVER,
						useClass: optionsOrFactory.profileResolver,
					}

		return [
			{
				inject: [
					{
						optional: true,
						token: ConfigService,
					},
				],
				provide: IAM_RESOLVED_OPTIONS,
				useFactory: (config?: ConfigService) =>
					IamModule._resolveOptions(optionsOrFactory, config),
			},
			{
				inject: [
					IAM_RESOLVED_OPTIONS,
				],
				provide: IAM_OPTIONS,
				useFactory: (options: IamModuleOptions): IamOptions => {
					const { imports, profileResolver, ...iamOptions } = options
					return iamOptions
				},
			},
			profileResolverProvider,
			AuthGuard,
			AclGuard,
			IamAclService,
			IamTokenService,
		]
	}
}
