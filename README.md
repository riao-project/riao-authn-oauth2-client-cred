# @riao/authn-oauth2-client-cred

OAuth2 Client Credentials (server-to-server) authentication driver for the RIAO Identity and Access Management framework.

## Overview

This driver implements the **OAuth2 Client Credentials flow**, enabling secure server-to-server API authentication. Each client application receives credentials (client_id and client_secret) that it can exchange for short-lived JWT access tokens.

**Key Features:**
- Client credential management with bcrypt hashing
- JWT token generation with configurable expiration
- Token signature verification for security
- Multiple credentials per principal (user/service)
- Credential revocation support
- Principal validation to prevent orphaned credentials
- Client ID format validation
- Usage tracking (last exchange time, failed attempt counter)
- Cryptographically secure secret generation utility
- Database persistence
- TypeScript support with full type safety

## Installation

```bash
npm install @riao/authn-oauth2-client-cred @riao/iam @riao/dbal
npm install --save-dev @riao/cli
```

## Quick Start

### 1. Database Setup

Create a migration to import the OAuth2 tables:

```bash
npx riao migration:create import-oauth2-client-cred-tables
```

In your migration file:

```typescript
import { OAuth2ClientCredentialsMigrations } from '@riao/authn-oauth2-client-cred';

export default OAuth2ClientCredentialsMigrations;
```

Run migrations:

```bash
npx riao migration:run
```

### 2. Initialize Authentication

```typescript
import { OAuth2ClientCredentialsAuthentication } from '@riao/authn-oauth2-client-cred';
import { Principal } from '@riao/iam/auth';

// Define your principal/user interface
interface User extends Principal {
  login: string;
}

// Create concrete authentication instance
class UserOAuth2Authentication extends OAuth2ClientCredentialsAuthentication<User> {}

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must contain at least 32 characters');
}

const oauth2 = new UserOAuth2Authentication({
  db: database,
  jwtSecret,
  tokenExpiresIn: 3600, // 1 hour
});

// Access principals via the inherited principalRepo property
const userId = 'user-123';
const principal = await oauth2.principalRepo.findOne({
  where: { id: userId },
});
```

### 3. Create Client Credentials

```typescript
// Generate a cryptographically secure secret
import { generateSecret } from '@riao/authn-oauth2-client-cred';

const clientSecret = generateSecret(32); // 32-character random string

// Create credentials for a principal
await oauth2.createClientCredential({
  principalId: userId,
  clientId: 'my-app-client',
  clientSecret,
  description: 'My Application',
});
```

**Client ID Validation:**
- Must be 3-255 characters long
- Can only contain: alphanumeric, hyphens (`-`), underscores (`_`), dots (`.`), colons (`:`)
- Examples: `my-app`, `service_prod.v2`, `client:region:001`

**Principal Validation:**
- The principal ID must exist and be active
- If the principal doesn't exist, credential creation fails with a clear error

**Client Secret Validation:**
- Client secrets must be at least 32 characters long. Use a cryptographically secure random value such as one returned by `generateSecret()`.

**Throws:** Error if:
- Client ID format is invalid
- Client secret is shorter than 32 characters
- Client ID is already in use (globally unique)
- Principal doesn't exist or is inactive

### 4. Exchange Credentials for Token

Server-to-server authentication flow:

```typescript
// Exchange client credentials for access token
const tokenResponse = await oauth2.exchangeCredentials(
  'my-app-client',
  'super-secret-password'
);

console.log(tokenResponse);
// {
//   access_token: 'eyJhbGc...',
//   token_type: 'Bearer',
//   expires_in: 3600
// }
```

### 5. Verify Access Tokens

On the API side, verify received tokens:

```typescript
const payload = await oauth2.verifyAccessToken(accessToken);

if (payload) {
  console.log('Token is valid');
  console.log('Client ID:', payload.client_id);
  console.log('Principal ID:', payload.principal_id);
} else {
  console.log('Token is invalid or expired');
}
```

## API Reference

### `generateSecret(length?)`

Generate a cryptographically secure random secret for client credentials.

**Parameters:**
- `length` (number, optional) - Length of secret in characters (default: 32)

**Returns:** Alphanumeric random string of specified length

**Example:**
```typescript
import { generateSecret } from '@riao/authn-oauth2-client-cred';

const secret = generateSecret(32);
// 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
```

### `exchangeCredentials(clientId, clientSecret)`

Exchange client credentials for a JWT access token.

**Parameters:**
- `clientId` (string) - Unique client identifier
- `clientSecret` (string) - Client secret (will be compared against bcrypt hash)

**Returns:** Object with `access_token`, `token_type: 'Bearer'`, and `expires_in` (seconds)

**Tracking:**
- Updates `last_exchange_timestamp` on successful exchange
- Increments `failed_exchange_count` on failed attempts
- Resets `failed_exchange_count` to 0 on successful exchange

**Throws:** Error if:
- Credential not found (`"Invalid credentials"`)
- Credential is revoked (`"Credential has been revoked"`)
- Secret doesn't match (`"Invalid credentials"`)
- Principal not found (rare edge case)

### `verifyAccessToken(token)`

Verify and decode a JWT access token.

**Parameters:**
- `token` (string) - JWT access token

**Returns:** Token payload with `client_id`, `principal_id`, `iat`, `exp` if valid; null if invalid/expired

### `createClientCredential(options)`

Create new client credentials for a principal.

**Parameters (`options`):**
- `principalId` - The principal (user/service) ID (must exist and be active)
- `clientId` - Unique identifier (3-255 chars, alphanumeric + `-`, `_`, `.`, `:`)
- `clientSecret` - Secret (will be bcrypt hashed, never stored in plain text)
- `description` - Optional description for the credential

**Returns:** Promise that resolves when credential is created

**Validation:**
- Principal must exist and be active
- Client ID must follow format rules
- Client ID must be globally unique (cannot reuse revoked client IDs)

**Throws:** Error if:
- Principal doesn't exist or is inactive
- Client ID format is invalid
- Client ID is already in use

### `revokeClientCredential(credentialId)`

Revoke a specific credential, preventing future token generation.

### `revokeAllCredentials(principalId)`

Revoke all active credentials for a principal.

### `listCredentials(principalId)`

List all active credentials for a principal (secrets are not included).

## Usage Tracking & Monitoring

Credentials automatically track exchange activity for security monitoring:

### Fields

- **`last_exchange_timestamp`** - When the credential was last used successfully
- **`failed_exchange_count`** - Number of failed authentication attempts since last success

### Example: Detect Compromised Credentials

```typescript
const credentials = await oauth2.listCredentials(principalId);

for (const cred of credentials) {
  // Alert if there are many failed attempts
  if (cred.failed_exchange_count > 5) {
    console.warn(`Suspicious activity on ${cred.client_id}: ${cred.failed_exchange_count} failed attempts`);
    // Consider revoking the credential
    await oauth2.revokeClientCredential(cred.id);
  }

  // Alert if not used recently
  if (cred.last_exchange_timestamp) {
    const daysSinceUse = (Date.now() - cred.last_exchange_timestamp.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceUse > 30) {
      console.info(`Credential ${cred.client_id} unused for ${Math.floor(daysSinceUse)} days`);
    }
  }
}
```

## Security Considerations

### Production Checklist

- ✅ Store `jwtSecret` in environment variables, never in code
- ✅ Use strong, random JWT secrets (32+ characters)
- ✅ Set appropriate `tokenExpiresIn` (recommend 1 hour for short-lived tokens)
- ✅ Keep client secrets confidential—display only when created
- ✅ Implement credential rotation policies
- ✅ Monitor and audit credential usage
- ✅ Revoke credentials when applications are decommissioned
- ✅ Use HTTPS for all token exchanges

### Token Expiration

- Default: 3600 seconds (1 hour)
- Short-lived tokens (< 1 hour) recommended
- Clients should request new tokens before expiration
- Expired tokens cannot be refreshed—must exchange credentials again

### Secret Hashing

- Client secrets are hashed using bcrypt before storage
- Secrets are never returned from the API
- Only the principal who created the credential knows the secret

## Examples

See [examples/](examples/) for complete, runnable examples:

**CLI Example** (`server-example.ts`)
- Demonstrates all OAuth2 operations
- Shows credential lifecycle (create, exchange, verify, revoke)
- Useful for understanding the authentication flow
- Run: `npm start`

## Contributing & Development

See [CONTRIBUTING.md](docs/contributing/contributing.md) for information on development.
