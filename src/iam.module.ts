import { type DynamicModule, Module } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

import { IAM_OPTIONS } from '@/iam.constants.js'
import type { IamModuleOptions } from '@/iam.types.js'

import { AclGuard } from '@/acl/acl.guard.js'
import { AclService } from '@/acl/acl.service.js'
import { AuthGuard } from '@/auth/auth.guard.js'
import { IamCryptoService } from '@/crypto/crypto.service.js'
import { IamTokenService } from '@/token/token.service.js'

@Module({})
export class IamModule {
	static register(options: IamModuleOptions): DynamicModule {
		return {
			exports: [
				IAM_OPTIONS,
				AuthGuard,
				AclGuard,
				AclService,
				IamTokenService,
				IamCryptoService,
			],
			global: true,
			imports: options.imports ?? [],
			module: IamModule,
			providers: [
				{
					inject: [
						ConfigService,
						...(options.inject ?? []),
					],
					provide: IAM_OPTIONS,
					useFactory: options.useFactory,
				},
				AuthGuard,
				AclGuard,
				AclService,
				IamTokenService,
				IamCryptoService,
			],
		}
	}
}
