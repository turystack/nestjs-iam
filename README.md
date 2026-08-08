# @turystack/nestjs-iam

JWT authentication and CASL-based ACL for NestJS with guard decorators and workspace/organization scoping.

## Installation

```bash
pnpm add @turystack/nestjs-iam
```

### Peer dependencies

The host application provides these:

```bash
pnpm add @nestjs/common @nestjs/core @turystack/nestjs-config reflect-metadata
```

Optional — install only the ones whose feature you use:

```bash
pnpm add @turystack/nestjs-context
```

## Documentation

Options, API reference and examples:

**https://tury.dev/libs/nestjs-iam**

## Development

```bash
pnpm install
pnpm typecheck
pnpm check
pnpm test
pnpm build
```
