import { UnauthorizedException } from '@nestjs/common'

export class IamUnauthorizedException extends UnauthorizedException {
	constructor(message = 'Unauthorized.') {
		super(message)
	}
}
