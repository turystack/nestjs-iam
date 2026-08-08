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
export class IamAclService {
	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
	) {}

	/**
	 * Abilities are the union of the organization role and the workspace role.
	 * Organization grants are conditioned on `organizationId` (valid in any
	 * workspace); workspace grants also carry the role's `workspaceId`, so
	 * they never leak into other workspaces or organization-level checks.
	 *
	 * `organization:manage` grants everything in the organization;
	 * `workspace:manage` grants everything within the role's workspace.
	 */
	private defineAbilities(user: IamProfile) {
		const { can, build } = new AbilityBuilder(Ability)

		const grant = (permissionIds: string[], condition: MongoQuery) => {
			for (const permission of permissionIds) {
				const [subject, action] = permission.split(':')

				if (subject === 'organization' && action === 'manage') {
					can('manage', 'all', {
						organizationId: user.organizationId,
					})
				} else if (
					subject === 'workspace' &&
					action === 'manage' &&
					'workspaceId' in condition
				) {
					can('manage', 'all', condition)
				} else if (action === 'manage') {
					const actions = this.options.permissions[subject] ?? []

					for (const expanded of actions.filter((a) => a !== 'manage')) {
						can(expanded, subject, condition)
					}
				} else {
					can(action, subject, condition)
				}
			}
		}

		if (user.organizationRole) {
			grant(user.organizationRole.permissionIds, {
				organizationId: user.organizationId,
			})
		}

		if (user.workspaceRole) {
			grant(user.workspaceRole.permissionIds, {
				organizationId: user.organizationId,
				workspaceId: user.workspaceRole.workspaceId,
			})
		}

		return build()
	}

	public canPerformAction(
		user: IamProfile,
		permission: string,
		context?: IamAclContext,
	) {
		const ability = this.defineAbilities(user)
		const [subject, action] = permission.split(':')

		// The checked resource: the user's organization, plus whatever the
		// route declares. Workspace grants carry a workspaceId condition, so
		// they only match when the route declares the same workspace — they
		// never authorize organization-level routes, and a mismatched context
		// id simply fails the conditions.
		const resource = {
			organizationId: user.organizationId,
			...context,
		}

		const authorized = ability.can(
			action,
			subjectFactory(subject, {
				type: subject,
				...resource,
			}),
		)

		if (!authorized) {
			throw new IamForbiddenException()
		}
	}
}
