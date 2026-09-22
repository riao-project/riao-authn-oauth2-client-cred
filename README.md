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

const oauth2 = new UserOAuth2Authentication({
  db: database,
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
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
// Create credentials for a principal
await oauth2.createClientCredential(
  userId,
  'my-app-client',
  'super-secret-password',
  'My Application'
);
```

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

### `exchangeCredentials(clientId, clientSecret)`

Exchange client credentials for a JWT access token.

**Parameters:**
- `clientId` (string) - Unique client identifier
- `clientSecret` (string) - Client secret (will be compared against bcrypt hash)

**Returns:** Object with `access_token`, `token_type: 'Bearer'`, and `expires_in` (seconds)

**Throws:** Error if client_id not found or secret doesn't match

### `verifyAccessToken(token)`

Verify and decode a JWT access token.

**Parameters:**
- `token` (string) - JWT access token

**Returns:** Token payload with `client_id`, `principal_id`, `iat`, `exp` if valid; null if invalid/expired

### `createClientCredential(principalId, clientId, clientSecret, description?)`

Create new client credentials for a principal.

**Parameters:**
- `principalId` - The principal (user/service) ID
- `clientId` - Unique identifier (must be unique across system)
- `clientSecret` - Secret (will be bcrypt hashed)
- `description` - Optional description for the credential

**Returns:** Promise that resolves when credential is created

### `revokeClientCredential(credentialId)`

Revoke a specific credential, preventing future token generation.

### `revokeAllCredentials(principalId)`

Revoke all active credentials for a principal.

### `listCredentials(principalId)`

List all active credentials for a principal (secrets are not included).

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
