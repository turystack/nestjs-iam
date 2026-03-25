import { ForbiddenException } from '@nestjs/common'

export class IamForbiddenException extends ForbiddenException {
	constructor(message = 'You are not authorized to perform this action.') {
		super(message)
	}
}
