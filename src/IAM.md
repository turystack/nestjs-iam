# IAM

JWT authentication and CASL-based ACL for NestJS. One central organization, N workspaces: tokens are minted for at most one workspace, and each user has at most one organization role plus one role in the minted workspace. No config framework is assumed.

## Setup

Register the module **once** in the app root. Registration is global: guards and services are shared app-wide — domain packages just inject `IamTokenService` / `IamAclService`.

```ts
import { Injectable, Module } from '@nestjs/common'
import { ConfigModule, defineConfigSchema } from '@turystack/nestjs-config'
import { IamModule, type IamPermissions, type IamProfile, type IamProfileResolver } from '@turystack/nestjs-iam'
import { type User, UserRepository } from '@repo/identity'
import { z } from 'zod'

// the validated environment the factory form reads from...
export const configSchema = defineConfigSchema({
  JWT_SECRET: z.string(),
})

declare module '@turystack/nestjs-config' {
  interface ConfigSchemaRegistry {
    schema: typeof configSchema
  }
}

// everything IAM needs lives here: the permission catalog...
const PERMISSIONS: IamPermissions = {
  user: ['create', 'read', 'update', 'delete'],
  workspace: ['manage', 'create', 'read', 'update', 'delete'],
  organization: ['manage', 'read', 'update'],
}

// ...and the resolver — the single bridge to your domain packages
@Injectable()
class ProfileResolverService implements IamProfileResolver {
  constructor(private readonly userRepository: UserRepository) {}

  // workspaceId = the workspace the token was minted for (absent on
  // organization-only tokens)
  async resolveProfile(userId: string, workspaceId?: string): Promise<IamProfile | null> {
    const user = await this.userRepository.findById(userId)
    return user ? this.toProfile(user, workspaceId) : null
  }

  // maps your domain user to the shape IAM expects
  private toProfile(user: User, workspaceId?: string): IamProfile {
    const membership = workspaceId
      ? user.memberships.find((m) => m.workspaceId === workspaceId)
      : undefined

    return {
      userId: user.id,
      organizationId: user.organizationId,
      organizationRole: user.organizationRole && {
        roleId: user.organizationRole.id,
        name: user.organizationRole.name,
        permissionIds: user.organizationRole.permissionIds,
      },
      workspaceRole: membership && {
        workspaceId: membership.workspaceId,
        roleId: membership.role.id,
        name: membership.role.name,
        permissionIds: membership.role.permissionIds,
      },
    }
  }
}

@Module({
  imports: [
    ConfigModule.register({ schema: configSchema }),
    IamModule.register((config) => ({
      secret: config.get('JWT_SECRET'),
      permissions: PERMISSIONS,
      profileResolver: ProfileResolverService,
    })),
  ],
})
export class AppModule {}
```

`register` also accepts a plain options object; the `(config) => options` form injects the `ConfigService` from `@turystack/nestjs-config` at boot. `imports` is only available in the plain form — in the factory form the resolver's dependencies must come from global modules.

### IamModuleOptions

| Property | Type | Required | Description |
|---|---|---|---|
| `secret` | `string` | Yes | HS256 secret for signing and verifying tokens |
| `permissions` | `Record<string, string[]>` | Yes | Actions per subject; the ACL engine expands `manage` into them |
| `profileResolver` | `Type<IamProfileResolver>` | Yes | Class with `resolveProfile(userId)` — instantiated via DI |
| `imports` | `ModuleMetadata['imports']` | No | Modules providing the resolver's dependencies, when not global |
| `tokenSource` | `'header' \| 'cookie' \| 'both'` | No | Where the guard reads the access token. Default `header` |
| `cookieName` | `string` | No | Cookie carrying the access token when `tokenSource` reads cookies. Default `session` |
| `accessExpiresIn` | `string` | No | Access token TTL (`s/m/h/d` units). Default `15m` |
| `refreshExpiresIn` | `string` | No | Refresh token TTL. Default `7d` |

## Routes

```ts
import { ACL, Auth, AuthenticatedProfile } from '@turystack/nestjs-iam'
import type { IamProfile } from '@turystack/nestjs-iam'

@Controller()
class AppController {
  // authentication only
  @Auth()
  @Get('me')
  me(@AuthenticatedProfile() profile: IamProfile) {
    return profile
  }

  // organization-level route (e.g. billing) — no context needed
  @ACL('billing:read')
  @Get('billing')
  billing() { ... }

  // workspace-level route — declare the workspace from the request
  @ACL('product:create', (request) => ({ workspaceId: request.params.workspaceId }))
  @Post('workspaces/:workspaceId/products')
  createProduct() { ... }
}
```

How the check works — abilities are the **union** of the two roles:

- Organization grants are conditioned on `organizationId` and apply on organization-level routes and in any workspace.
- Workspace grants also carry the role's `workspaceId`: they only match when the route declares the same workspace — they never authorize organization-level routes nor other workspaces.
- `organization:manage` grants everything in the organization; `workspace:manage` grants everything within the role's workspace.

## Where the token comes from

By default the guard reads `Authorization: Bearer <token>`, which is what a
native or server-to-server client sends.

A browser is the case that differs. A token the page can read is a token a
script on the page can exfiltrate, so a web session is better delivered as an
httpOnly cookie — unreadable by JavaScript, sent by the browser on its own.

```ts
IamModule.register((config) => ({
  secret: config.get('IAM_SECRET'),
  permissions: PERMISSIONS,
  profileResolver: ProfileResolverService,
  tokenSource: 'cookie',   // 'header' (default) | 'cookie' | 'both'
  cookieName: 'session',   // default 'session'
}))
```

Use `both` when one API serves a web app and a mobile app: the header is read
first, so an explicit bearer always wins over an ambient cookie.

The cookie is read from `request.cookies` when a cookie parser populated it, and
from the raw `Cookie` header otherwise — authenticating never depends on a
middleware someone forgot to install.

## Tokens

```ts
import { IamTokenService } from '@turystack/nestjs-iam'

@Injectable()
class AuthFlowService {
  constructor(private readonly tokens: IamTokenService) {}

  // tokens are minted for at most one workspace; switching workspaces
  // (or entering an organization-only page) issues new tokens
  async login(userId: string, workspaceId?: string) {
    // { accessToken, refreshToken, expiresIn }
    return this.tokens.issueTokens(userId, { workspaceId })
  }

  async refresh(refreshToken: string) {
    // throws IamUnauthorizedException on any invalid/expired token
    const { userId, workspaceId } = await this.tokens.verifyRefreshToken(refreshToken)
    return this.tokens.issueTokens(userId, { workspaceId })
  }
}
```

## Exceptions

| Exception | HTTP | When |
|---|---|---|
| `IamUnauthorizedException` | 401 | Missing/invalid/expired token, unresolvable profile |
| `IamForbiddenException` | 403 | Permission check failed |

## Types

```ts
type IamProfile = {
  userId: string
  organizationId: string
  organizationRole?: IamRole // role in the organization as a whole
  workspaceRole?: IamWorkspaceRole // role in the workspace the token was minted for
}

type IamRole = {
  roleId: string
  name: string
  permissionIds: string[] // e.g. ['product:create', 'workspace:manage']
}

type IamWorkspaceRole = IamRole & { workspaceId: string }
```
