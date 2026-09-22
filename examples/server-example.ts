/**
 * OAuth2 Client Credentials Authentication Example
 *
 * This example demonstrates the complete OAuth2 Client Credentials flow
 * with production-ready JWT token management.
 *
 * Features demonstrated:
 * - Creating OAuth2 credentials for principals
 * - Exchanging credentials for JWT access tokens
 * - Verifying access tokens
 * - Managing credentials (list, revoke)
 * - Protected endpoints using Bearer tokens
 *
 * Run with: npm start
 */

import { OAuth2ClientCredentialsAuthentication } from '../src';
import { exampledb } from '../database/example';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import { OAuth2ClientCredentialsMigrations } from '../src/oauth2-client-credentials-migrations';
import { MigrationRunner, Migration } from '@riao/dbal';
import { Principal } from '@riao/iam/auth';

/* eslint-disable no-console */

/**
 * Example user/principal interface
 */
interface User extends Principal {
	login: string;
	name: string;
}

/**
 * Concrete implementation of OAuth2 authentication
 */
class UserOAuth2Authentication extends OAuth2ClientCredentialsAuthentication<User> {}

async function main(): Promise<void> {
	try {
		console.log('🔐 OAuth2 Client Credentials Example\n');

		// Initialize database
		console.log('📦 Initializing database...');
		await exampledb.init();
		console.log('✓ Database initialized');

		// Run migrations to create schema
		console.log('📋 Running migrations...');
		const runner = new MigrationRunner(exampledb);

		// Get and run auth migrations
		const authMigrations = new AuthMigrations();
		const authMigrationsMap = await authMigrations.getMigrations();
		const authMigrationClasses = Object.entries(authMigrationsMap).reduce(
			(acc, [key, MigrationClass]) => {
				acc[key] = new (MigrationClass as typeof Migration)(exampledb);
				return acc;
			},
			{} as Record<string, Migration>
		);
		await runner.run(authMigrationClasses);

		// Get and run OAuth2 migrations
		const oauth2Migrations = new OAuth2ClientCredentialsMigrations();
		const oauth2MigrationsMap = await oauth2Migrations.getMigrations();
		const oauth2MigrationClasses = Object.entries(
			oauth2MigrationsMap
		).reduce(
			(acc, [key, MigrationClass]) => {
				acc[key] = new (MigrationClass as typeof Migration)(exampledb);
				return acc;
			},
			{} as Record<string, Migration>
		);
		await runner.run(oauth2MigrationClasses);
		console.log('✓ Schema ready\n');

		// Create authentication instance
		const secret = process.env['JWT_SECRET'] || 'demo-secret-key-change';
		const oauth2 = new UserOAuth2Authentication({
			db: exampledb,
			jwtSecret: secret,
			tokenExpiresIn: 3600, // 1 hour
		});

		// Use a demo principal ID
		// In production, principals may be created separately via your
		// user management system or by calling: oauth2.principalRepo.insertOne()
		// For this example, we'll use a static UUID
		const userId = '550e8400-e29b-41d4-a716-446655440000'; // UUIDv4

		// Note: Create the principal in your real application
		// For this example, we'll create it to demonstrate full workflow
		const principalExists = await oauth2.principalRepo.findOne({
			where: { id: userId },
		});

		if (!principalExists) {
			// Principal doesn't exist, create it for this example
			const principalRepo = oauth2.principalRepo as any;
			if (principalRepo.insertOne) {
				await principalRepo.insertOne({
					record: {
						id: userId,
						login: 'demo-user',
						type: 'user',
						name: 'Demo User',
					},
				});
				console.log('✓ Demo principal created\n');
			}
		}

		console.log(`Using principal ID: ${userId}\n`);

		// Example 1: Create client credentials
		console.log('--- Creating Client Credentials ---');
		const clientId = `my-service-${Date.now()}`;
		const clientSecret = 'super-secret-password-12345';

		await oauth2.createClientCredential(
			userId,
			clientId,
			clientSecret,
			'My Service Application'
		);
		console.log('✓ Credentials created');
		console.log(`  Client ID: ${clientId}`);
		console.log(`  Client Secret: ${clientSecret} (keep this safe!)\n`);

		// Example 2: Exchange credentials for access token
		console.log('--- Exchanging Credentials for Token ---');
		const tokenResponse = await oauth2.exchangeCredentials(
			clientId,
			clientSecret
		);
		console.log('✓ Access token received');
		console.log(
			`  Token: ${tokenResponse.access_token.substring(0, 50)}...`
		);
		console.log(`  Expires in: ${tokenResponse.expires_in}s`);
		console.log(`  Type: ${tokenResponse.token_type}\n`);

		// Example 3: Verify access token
		console.log('--- Verifying Access Token ---');
		const payload = await oauth2.verifyAccessToken(
			tokenResponse.access_token
		);
		if (payload) {
			console.log('✓ Token is valid');
			console.log(`  Client ID: ${payload.client_id}`);
			console.log(`  Principal ID: ${payload.principal_id}`);
			console.log(
				`  Token will expire in: ${tokenResponse.expires_in}s\n`
			);
		}

		// Example 4: List credentials
		console.log('--- Listing Active Credentials ---');
		const credentials = await oauth2.listCredentials(userId);
		console.log(`✓ Found ${credentials.length} credential(s)`);
		credentials.forEach((cred, i) => {
			console.log(`  ${i + 1}. ${cred.client_id} - ${cred.description}`);
		});
		console.log();

		// Example 5: Try with wrong secret (should fail)
		console.log('--- Testing with Invalid Secret ---');
		try {
			await oauth2.exchangeCredentials(clientId, 'wrong-secret');
			console.log('✗ Should have thrown error');
		}
		catch (error) {
			console.log(`✓ Correctly rejected: ${(error as Error).message}\n`);
		}

		// Example 6: Create another credential for same principal
		console.log('--- Creating Second Credential ---');
		const clientId2 = `my-service-v2-${Date.now()}`;
		const clientSecret2 = 'another-secret-password-67890';

		await oauth2.createClientCredential(
			userId,
			clientId2,
			clientSecret2,
			'My Service v2 (backup)'
		);
		console.log(`✓ Second credential created: ${clientId2}\n`);

		// Example 7: List again (should have 2)
		console.log('--- Listing Credentials After Adding Second ---');
		const credentials2 = await oauth2.listCredentials(userId);
		console.log(`✓ Found ${credentials2.length} credential(s)`);
		credentials2.forEach((cred, i) => {
			console.log(`  ${i + 1}. ${cred.client_id}`);
		});
		console.log();

		// Example 8: Revoke the credential created in Example 1
		console.log('--- Revoking First Credential ---');
		const credentialToRevoke = credentials2.find(
			(c) => c.client_id === clientId
		);
		if (credentialToRevoke?.id) {
			await oauth2.revokeClientCredential(credentialToRevoke.id);
			console.log(`✓ Revoked: ${credentialToRevoke.client_id}\n`);
		}

		// Example 9: Verify revoked credential no longer works
		console.log('--- Testing Revoked Credential ---');
		try {
			await oauth2.exchangeCredentials(clientId, clientSecret);
			console.log('✗ Should have thrown error');
		}
		catch (error) {
			console.log(`✓ Correctly rejected: ${(error as Error).message}\n`);
		}

		// Example 10: Active credential still works
		console.log('--- Testing Active Credential ---');
		const tokenResponse2 = await oauth2.exchangeCredentials(
			clientId2,
			clientSecret2
		);
		console.log('✓ Successfully obtained token with second credential');
		console.log(
			`  Token: ${tokenResponse2.access_token.substring(0, 50)}...\n`
		);

		console.log('✅ All examples completed successfully!\n');
	}
	catch (error) {
		console.error('❌ Error:', error);
		process.exit(1);
	}
}

// Run the example
void main();
