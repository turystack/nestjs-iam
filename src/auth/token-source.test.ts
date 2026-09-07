import { describe, expect, it } from 'vitest'

import { readAccessToken, readCookie } from './token-source.js'

describe('readCookie', () => {
	it('prefers a parsed cookie when a cookie parser installed one', () => {
		expect(
			readCookie(
				{
					cookies: {
						session: 'parsed',
					},
					headers: {
						cookie: 'session=raw',
					},
				},
				'session',
			),
		).toBe('parsed')
	})

	it('falls back to the raw header, so no cookie parser is required', () => {
		expect(
			readCookie(
				{
					headers: {
						cookie: 'other=1; session=from-header; another=2',
					},
				},
				'session',
			),
		).toBe('from-header')
	})

	it('decodes an encoded value', () => {
		expect(
			readCookie(
				{
					headers: {
						cookie: 'session=a%20b',
					},
				},
				'session',
			),
		).toBe('a b')
	})

	it('does not match a cookie whose name merely ends with the one asked for', () => {
		expect(
			readCookie(
				{
					headers: {
						cookie: 'not-session=wrong',
					},
				},
				'session',
			),
		).toBeUndefined()
	})

	it('returns undefined for an empty value rather than an empty token', () => {
		expect(
			readCookie(
				{
					headers: {
						cookie: 'session=',
					},
				},
				'session',
			),
		).toBeUndefined()
	})

	it('returns undefined when there is no cookie at all', () => {
		expect(
			readCookie(
				{
					headers: {},
				},
				'session',
			),
		).toBeUndefined()
	})
})

describe('readAccessToken', () => {
	const request = {
		cookies: {
			session: 'cookie-token',
		},
		headers: {
			authorization: 'Bearer header-token',
		},
	}

	it('reads the header by default, so an existing application is unchanged', () => {
		expect(readAccessToken(request, {})).toBe('header-token')
	})

	it('reads only the cookie when the source is cookie', () => {
		expect(
			readAccessToken(request, {
				tokenSource: 'cookie',
			}),
		).toBe('cookie-token')
	})

	it('ignores the header when the source is cookie and no cookie is set', () => {
		expect(
			readAccessToken(
				{
					headers: {
						authorization: 'Bearer header-token',
					},
				},
				{
					tokenSource: 'cookie',
				},
			),
		).toBeUndefined()
	})

	it('prefers an explicit bearer over an ambient cookie when both are allowed', () => {
		expect(
			readAccessToken(request, {
				tokenSource: 'both',
			}),
		).toBe('header-token')
	})

	it('falls back to the cookie when both are allowed and no header is sent', () => {
		expect(
			readAccessToken(
				{
					cookies: {
						session: 'cookie-token',
					},
					headers: {},
				},
				{
					tokenSource: 'both',
				},
			),
		).toBe('cookie-token')
	})

	it('honours a custom cookie name', () => {
		expect(
			readAccessToken(
				{
					headers: {
						cookie: 'acme_session=named',
					},
				},
				{
					cookieName: 'acme_session',
					tokenSource: 'cookie',
				},
			),
		).toBe('named')
	})
})
