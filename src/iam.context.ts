import type { IamProfile } from '@/iam.types.js'

/** Publishes the authenticated profile into the operation's context. */
export type IamContextPublisher = (profile: IamProfile) => void

let publish: IamContextPublisher | undefined
let resolved = false

/**
 * Resolves `ContextService.setActor` from `@turystack/nestjs-context`.
 *
 * Optional peer, imported lazily and cached: an application that does not
 * propagate context authenticates exactly the same, it just does not stamp the
 * actor on audited writes.
 */
async function resolvePublisher(): Promise<IamContextPublisher | undefined> {
	if (resolved) {
		return publish
	}

	resolved = true

	try {
		const { getCurrentContext } = await import('@turystack/nestjs-context')

		publish = (profile) => {
			const context = getCurrentContext()

			if (!context) {
				return
			}

			// Mutated rather than opened: the entrypoint already opened the scope
			// with the correlation id, and authentication only now knows who is
			// acting. Opening a new one here would sever the chain.
			context.actor = {
				id: profile.userId,
				organizationId: profile.organizationId,
			}
			context.tenantId = profile.organizationId
		}
	} catch {
		publish = undefined
	}

	return publish
}

/**
 * Publishes the authenticated profile so downstream code — logging, auditing,
 * tracing — sees who is acting without receiving it as an argument.
 *
 * No-op outside a context scope, and when the context package is absent.
 */
export async function publishProfileToContext(
	profile: IamProfile,
): Promise<void> {
	const publisher = await resolvePublisher()

	publisher?.(profile)
}

/** Test seam — forces the next call to resolve again. */
export function resetIamContextPublisher(): void {
	publish = undefined
	resolved = false
}
