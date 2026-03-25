import {
	Ability,
	AbilityBuilder,
	type MongoQuery,
	subject as subjectFactory,
} from '@casl/ability'
import { Inject, Injectable } from '@nestjs/common'

import { IAM_OPTIONS } from '@/iam.constants.js'
import type { IamAclContext, IamOptions, IamProfile } from '@/iam.types.js'

import { IamForbiddenException } from '@/exceptions/iam-forbidden.exception.js'

@Injectable()
export class AclService {
	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
	) {}

	private defineAbilities(
		user: IamProfile,
		options: {
			organizationId?: string
		},
	) {
		const { can, build } = new AbilityBuilder(Ability)

		const permissions =
			(options.organizationId
				? user.scopes.find(
						(scope) =>
							scope.organization?.organizationId === options.organizationId ||
							scope.kind === 'WORKSPACE',
					)?.permissionIds
				: user.scopes.find((scope) => scope.kind === 'WORKSPACE')
						?.permissionIds) ?? []

		const condition: MongoQuery = {
			workspaceId: user.workspaceId,
		}

		permissions.forEach((permission) => {
			const [subject, action] = permission.split(':')

			if (subject === 'workspace' && action === 'manage') {
				can('manage', 'all', {
					workspaceId: user.workspaceId,
				})
			} else if (action === 'manage') {
				const actions = this.options.permissions[subject] ?? []

				actions
					.filter((a) => a !== 'manage')
					.forEach((a) => {
						can(a, subject, condition)
					})
			} else {
				can(action, subject, condition)
			}
		})

		return build()
	}

	public canPerformAction(
		user: IamProfile,
		permission: string,
		resource?: IamAclContext,
	) {
		const ability = this.defineAbilities(user, {
			organizationId: resource?.organizationId,
		})

		const permissionsToCheck: string[] = [
			permission,
			'workspace:manage',
		]

		if (resource?.organizationId) {
			permissionsToCheck.push('organization:manage')
		}

		const authorized = permissionsToCheck.some((perm) => {
			const [subject, action] = perm.split(':')

			return resource
				? ability.can(
						action,
						subjectFactory(subject, {
							type: subject,
							...resource,
						}),
					)
				: ability.can(action, subject)
		})

		if (!authorized) {
			throw new IamForbiddenException()
		}
	}
}
