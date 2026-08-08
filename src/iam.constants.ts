/** DI token for the IAM options (secret, permissions, TTLs). */
export const IAM_OPTIONS = Symbol('IAM_OPTIONS')

/** DI token for the app's {@link IamProfileResolver} implementation. */
export const IAM_PROFILE_RESOLVER = Symbol('IAM_PROFILE_RESOLVER')

/** Metadata key used by the @ACL decorator. */
export const ACL_KEY = 'iam:acl'
