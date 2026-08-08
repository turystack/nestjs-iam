import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { describe, expect, it } from 'vitest'

import { ACL_KEY } from '@/iam.constants.js'
import type { IamAclMetadata } from '@/iam.types.js'

import { AclGuard } from '@/acl/acl.guard.js'
import { AuthGuard } from '@/auth/auth.guard.js'
import { ACL } from '@/decorators/acl.decorator.js'
import { Auth } from '@/decorators/auth.decorator.js'
import {
	Profile,
	profileFactory,
} from '@/decorators/authenticated-profile.decorator.js'

const getGuards = (target: object, propertyKey: string): unknown[] =>
	Reflect.getMetadata(
		'__guards__',
		Reflect.getOwnPropertyDescriptor(target, propertyKey)?.value ??
			Object.getOwnPropertyDescriptor(target, propertyKey)?.value,
	) ?? []

describe('decorators', () => {
	describe('@Auth', () => {
		it('should apply the AuthGuard', () => {
			class Controller {
				@Auth()
				handler() {}
			}

			const guards = getGuards(Controller.prototype, 'handler')
			expect(guards).toEqual([
				AuthGuard,
			])
		})
	})

	describe('@ACL', () => {
		it('should set the acl metadata and apply both guards', () => {
			const getContext = (request: {
				params: {
					workspaceId: string
				}
			}) => ({
				workspaceId: request.params.workspaceId,
			})

			class Controller {
				@ACL('user:read', getContext)
				handler() {}
			}

			const guards = getGuards(Controller.prototype, 'handler')
			expect(guards).toEqual([
				AuthGuard,
				AclGuard,
			])

			const reflector = new Reflector()
			const metadata = reflector.get<IamAclMetadata>(
				ACL_KEY,
				Controller.prototype.handler,
			)
			expect(metadata.permission).toBe('user:read')
			expect(
				metadata.getContext?.({
					params: {
						workspaceId: 'ws-1',
					},
				}),
			).toEqual({
				workspaceId: 'ws-1',
			})
		})
	})

	describe('@Profile', () => {
		it('should return request.user from the execution context', () => {
			const user = {
				userId: 'u1',
			}
			const context = {
				switchToHttp: () => ({
					getRequest: () => ({
						user,
					}),
				}),
			} as unknown as ExecutionContext

			expect(profileFactory(undefined, context)).toBe(user)
			expect(typeof Profile).toBe('function')
		})
	})
})
