import type { IamOptions, IamTokenSource } from '@/iam.types.js'

export const DEFAULT_COOKIE_NAME = 'session'

/**
 * Reads one cookie from a request.
 *
 * `request.cookies` is only populated when the application installed a cookie
 * parser, and a guard that silently authorizes nobody because a middleware is
 * missing is the worst kind of failure — it looks like a wrong password. So the
 * raw `Cookie` header is parsed as a fallback, and no consumer is forced to add
 * a dependency to authenticate.
 */
export function readCookie(
	request: {
		cookies?: Record<string, string | undefined>
		headers?: Record<string, string | string[] | undefined>
	},
	name: string,
): string | undefined {
	const parsed = request.cookies?.[name]

	if (parsed) {
		return parsed
	}

	const header = request.headers?.cookie

	if (typeof header !== 'string') {
		return undefined
	}

	for (const part of header.split(';')) {
		const separator = part.indexOf('=')

		if (separator === -1) {
			continue
		}

		if (part.slice(0, separator).trim() !== name) {
			continue
		}

		const value = part.slice(separator + 1).trim()

		return value.length > 0 ? decodeURIComponent(value) : undefined
	}

	return undefined
}

function readHeaderToken(request: {
	headers?: Record<string, string | string[] | undefined>
}): string | undefined {
	const authorization = request.headers?.authorization

	if (typeof authorization !== 'string') {
		return undefined
	}

	const [accessToken] = authorization.split(' ').reverse()

	return accessToken || undefined
}

/**
 * Where the access token comes from, per the module's configuration.
 *
 * A browser session delivered as an httpOnly cookie is unreadable by
 * JavaScript, which is the point: the token cannot be exfiltrated by a script
 * on the page. A native client has no cookie jar to rely on and keeps sending
 * `Authorization: Bearer`. `both` exists because one API commonly serves both,
 * and it reads the header first so an explicit bearer always wins over an
 * ambient cookie.
 */
export function readAccessToken(
	request: {
		cookies?: Record<string, string | undefined>
		headers?: Record<string, string | string[] | undefined>
	},
	options: Pick<IamOptions, 'cookieName' | 'tokenSource'>,
): string | undefined {
	const source: IamTokenSource = options.tokenSource ?? 'header'
	const cookieName = options.cookieName ?? DEFAULT_COOKIE_NAME

	if (source === 'header') {
		return readHeaderToken(request)
	}

	if (source === 'cookie') {
		return readCookie(request, cookieName)
	}

	return readHeaderToken(request) ?? readCookie(request, cookieName)
}
