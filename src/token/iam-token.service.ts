import { Inject, Injectable } from '@nestjs/common'
import { jwtVerify, SignJWT } from 'jose'

import { IAM_OPTIONS } from '@/iam.constants.js'
import type { IamOptions, TokenPair } from '@/iam.types.js'

import { IamUnauthorizedException } from '@/exceptions/iam-unauthorized.exception.js'

@Injectable()
export class IamTokenService {
	private readonly secretKey: Uint8Array

	constructor(
		@Inject(IAM_OPTIONS)
		private readonly options: IamOptions,
	) {
		this.secretKey = new TextEncoder().encode(options.secret)
	}

	/**
	 * Issues an access/refresh pair minted for at most one workspace: pass
	 * `workspaceId` when the user selected a workspace, omit it for
	 * organization-only sessions. Switching workspaces = issuing new tokens.
	 */
	async issueTokens(
		userId: string,
		options?: {
			workspaceId?: string
		},
	): Promise<TokenPair> {
		const accessExpiresIn = this.options.accessExpiresIn ?? '15m'
		const refreshExpiresIn = this.options.refreshExpiresIn ?? '7d'
		const workspaceClaim = options?.workspaceId
			? {
					workspaceId: options.workspaceId,
				}
			: {}

		const accessToken = await new SignJWT({
			userId,
			...workspaceClaim,
		})
			.setProtectedHeader({
				alg: 'HS256',
			})
			.setIssuedAt()
			.setExpirationTime(accessExpiresIn)
			.sign(this.secretKey)

		const refreshToken = await new SignJWT({
			rt: true,
			userId,
			...workspaceClaim,
		})
			.setProtectedHeader({
				alg: 'HS256',
			})
			.setIssuedAt()
			.setExpirationTime(refreshExpiresIn)
			.sign(this.secretKey)

		const expiresIn = this.parseExpiresIn(accessExpiresIn)

		return {
			accessToken,
			expiresIn,
			refreshToken,
		}
	}

	/** Returns the token subject and the workspace it was minted for, if any. */
	async verifyRefreshToken(token: string): Promise<{
		userId: string
		workspaceId?: string
	}> {
		try {
			const { payload } = await jwtVerify(token, this.secretKey, {
				algorithms: [
					'HS256',
				],
			})

			if (!payload.rt || typeof payload.userId !== 'string') {
				throw new IamUnauthorizedException()
			}

			return {
				userId: payload.userId,
				...(typeof payload.workspaceId === 'string'
					? {
							workspaceId: payload.workspaceId,
						}
					: {}),
			}
		} catch {
			throw new IamUnauthorizedException()
		}
	}

	private parseExpiresIn(value: string): number {
		const match = value.match(/^(\d+)([smhd])$/)

		if (!match) {
			return 3600
		}

		const amount = Number.parseInt(match[1], 10)
		const unit = match[2]
		const multipliers: Record<string, number> = {
			d: 86400,
			h: 3600,
			m: 60,
			s: 1,
		}

		return amount * (multipliers[unit] ?? 3600)
	}
}
