import { applyDecorators, UseGuards } from '@nestjs/common'

import { AuthGuard } from '@/auth/auth.guard.js'

export const Auth = () => applyDecorators(UseGuards(AuthGuard))
