import { getCurrentContext, runWithContext } from '@turystack/nestjs-context'
import { afterEach, describe, expect, it } from 'vitest'

import {
	publishProfileToContext,
	resetIamContextPublisher,
} from '@/iam.context.js'
import type { IamProfile } from '@/iam.types.js'

const profile: IamProfile = {
	organizationId: 'org-1',
	organizationRole: {
		name: 'Owner',
		permissionIds: [
			'order:read',
		],
		roleId: 'role-1',
	},
	userId: 'user-9',
}

afterEach(() => {
	resetIamContextPublisher()
})

describe('publishProfileToContext', () => {
	it('publishes the actor into the operation in flight', async () => {
		await runWithContext(
			{
				correlationId: 'req-1',
			},
			async () => {
				await publishProfileToContext(profile)

				expect(getCurrentContext()?.actor).toEqual({
					id: 'user-9',
					organizationId: 'org-1',
				})
			},
		)
	})

	it('publishes the organization as the tenant boundary', async () => {
		await runWithContext(
			{
				correlationId: 'req-1',
			},
			async () => {
				await publishProfileToContext(profile)

				expect(getCurrentContext()?.tenantId).toBe('org-1')
			},
		)
	})

	it('keeps the correlation id the entrypoint opened with', async () => {
		await runWithContext(
			{
				correlationId: 'req-7',
			},
			async () => {
				await publishProfileToContext(profile)

				// Authentication happens mid-request; opening a new scope here would
				// sever the chain that started at the edge.
				expect(getCurrentContext()?.correlationId).toBe('req-7')
			},
		)
	})

	it('is visible to code running later in the same operation', async () => {
		await runWithContext(
			{
				correlationId: 'req-2',
			},
			async () => {
				await publishProfileToContext(profile)
				await new Promise((tick) => setTimeout(tick, 5))

				expect(getCurrentContext()?.actor?.id).toBe('user-9')
			},
		)
	})

	it('does nothing outside a context scope', async () => {
		await expect(publishProfileToContext(profile)).resolves.toBeUndefined()
		expect(getCurrentContext()).toBeUndefined()
	})
})
