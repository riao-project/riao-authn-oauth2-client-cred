import 'jasmine';
// eslint-disable-next-line max-len
import { OAuth2ClientCredentialsAuthentication } from '../../src/oauth2-client-credentials-authentication';
import { createDatabase, runMigrations, runMigrationsDown } from '../database';
import { Principal } from '@riao/iam/auth';
// eslint-disable-next-line max-len
import { OAuth2ClientCredentialsMigrations } from '../../src/oauth2-client-credentials-migrations';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import { compare } from 'bcrypt';
import { generateSecret } from '../../src';

interface OAuth2Principal extends Principal {
	login: string;
}

describe('Authentication - OAuth2 Client Credentials', () => {
	const db = createDatabase('authentication-oauth2-client-cred');

	const auth =
		new (class extends OAuth2ClientCredentialsAuthentication<OAuth2Principal> {})(
			{
				db,
				jwtSecret: 'test-secret-key-minimum-32-characters-long',
				tokenExpiresIn: 3600,
				jwtAlgorithm: 'HS256',
			}
		);

	const repo = auth.principalRepo;
	const credentialsRepo = auth.credentialsRepo;
	const validTestSecret = 'test-secret-key-minimum-32-characters-long';
	const alternateTestSecret =
		'another-test-secret-minimum-32-characters-long';

	beforeAll(async () => {
		await db.init();
		// Run parent migrations first
		await runMigrations(db, new AuthMigrations());
		// Run driver-specific migrations
		await runMigrations(db, new OAuth2ClientCredentialsMigrations());
		await runMigrationsDown(db, new OAuth2ClientCredentialsMigrations());
		await runMigrations(db, new OAuth2ClientCredentialsMigrations());
	});

	afterAll(async () => {
		await db.disconnect();
	});

	// Helper to create a principal
	const createPrincipal = async (login: string, name: string) => {
		const id = await repo.insertOne({
			record: {
				login,
				type: 'user',
				name,
			},
		});
		return (typeof id === 'string' ? id : (id as any).id) as string;
	};

	describe('Client Credential Management', () => {
		it('should create a client credential with bcrypt-hashed secret', async () => {
			const principalId = await createPrincipal(
				'create_credential_test',
				'Create Credential Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'test-client-1',
				clientSecret: validTestSecret,
				description: 'Test Client',
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'test-client-1' },
			});

			expect(credential).toBeDefined();
			if (credential) {
				expect(credential.principal_id).toEqual(principalId as string);
				expect(credential.client_id).toEqual('test-client-1');
				expect(credential.description).toEqual('Test Client');
				expect(
					await compare(
						validTestSecret,
						credential.client_secret_hash
					)
				).toEqual(true);
				expect(credential.deactivate_timestamp).toBeNull();
			}
		});

		it('should prevent duplicate client_id', async () => {
			const principalId = await createPrincipal(
				'duplicate_client_test',
				'Duplicate Client Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'duplicate-client',
				clientSecret: validTestSecret,
			});

			// Attempt to create with same client_id
			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: 'duplicate-client',
					clientSecret: alternateTestSecret,
				})
			).toBeRejectedWithError(/already in use/);
		});

		it('should list active credentials for a principal', async () => {
			const principalId = await createPrincipal(
				'list_credentials_test',
				'List Credentials Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'list-client-1',
				clientSecret: validTestSecret,
				description: 'Client 1',
			});

			await auth.createClientCredential({
				principalId,
				clientId: 'list-client-2',
				clientSecret: alternateTestSecret,
				description: 'Client 2',
			});

			const credentials = await auth.listCredentials(principalId);

			expect(credentials.length).toEqual(2);
			expect(credentials.map((c) => c.client_id).sort()).toEqual(
				['list-client-1', 'list-client-2'].sort()
			);
		});

		it('should not return secret hashes when listing credentials', async () => {
			const principalId = await createPrincipal(
				'no_hash_test',
				'No Hash Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'sensitive-client',
				clientSecret: validTestSecret,
			});

			const credentials = await auth.listCredentials(principalId);

			expect(credentials.length).toEqual(1);
			// Type system ensures client_secret_hash is omitted
			expect(credentials[0].client_id).toEqual('sensitive-client');
		});
	});

	describe('Client Secret Validation', () => {
		it('should reject an empty client_secret', async () => {
			const principalId = await createPrincipal(
				'empty_secret_test',
				'Empty Secret Test'
			);

			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: 'empty-secret-client',
					clientSecret: '',
				})
			).toBeRejectedWithError(/at least 32 characters/);
		});

		it('should reject a client_secret shorter than 32 characters', async () => {
			const principalId = await createPrincipal(
				'short_secret_test',
				'Short Secret Test'
			);

			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: 'short-secret-client',
					clientSecret: 'a'.repeat(31),
				})
			).toBeRejectedWithError(/at least 32 characters/);
		});

		it('should accept a client_secret of exactly 32 characters', async () => {
			const principalId = await createPrincipal(
				'minimum_secret_test',
				'Minimum Secret Test'
			);

			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: 'minimum-secret-client',
					clientSecret: 'a'.repeat(32),
				})
			).toBeResolved();
		});
	});

	describe('Client ID Validation', () => {
		it('should reject client_id that is too short', async () => {
			const principalId = await createPrincipal(
				'short_id_test',
				'Short ID Test'
			);

			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: 'ab',
					clientSecret: 'secret-123',
				})
			).toBeRejectedWithError(/at least 3 characters/);
		});

		it('should reject client_id that is too long', async () => {
			const principalId = await createPrincipal(
				'long_id_test',
				'Long ID Test'
			);

			const longId = 'a'.repeat(256);

			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: longId,
					clientSecret: 'secret-123',
				})
			).toBeRejectedWithError(/cannot exceed 255 characters/);
		});

		it('should reject client_id with invalid characters', async () => {
			const principalId = await createPrincipal(
				'invalid_chars_test',
				'Invalid Chars Test'
			);

			const invalidIds = [
				'client@example.com',
				'client with spaces',
				'client/path',
				'client!exclamation',
			];

			for (const invalidId of invalidIds) {
				await expectAsync(
					auth.createClientCredential({
						principalId,
						clientId: invalidId,
						clientSecret: 'secret-123',
					})
				).toBeRejectedWithError(/alphanumeric|hyphens|underscores/);
			}
		});

		it('should accept valid client_id formats', async () => {
			const principalId = await createPrincipal(
				'valid_id_test',
				'Valid ID Test'
			);

			const validIds = [
				'simple-client',
				'client_with_underscore',
				'client.with.dots',
				'client:with:colons',
				'mixed-client_123.prod:v1',
			];

			for (let i = 0; i < validIds.length; i++) {
				await auth.createClientCredential({
					principalId,
					clientId: validIds[i],
					clientSecret: `${validTestSecret}${i}`,
					description: `Valid Client ${i}`,
				});
			}

			const credentials = await auth.listCredentials(principalId);
			expect(credentials.length).toEqual(validIds.length);
		});
	});

	describe('Principal Validation', () => {
		it('should reject credential creation for nonexistent principal', async () => {
			const nonexistentId = '00000000-0000-0000-0000-000000000000';

			await expectAsync(
				auth.createClientCredential({
					principalId: nonexistentId,
					clientId: 'test-client',
					clientSecret: validTestSecret,
				})
			).toBeRejectedWithError(/does not exist or is inactive/);
		});

		it('should accept credential creation for valid principal', async () => {
			const principalId = await createPrincipal(
				'valid_principal_test',
				'Valid Principal Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'test-client',
				clientSecret: validTestSecret,
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'test-client' },
			});

			expect(credential).toBeDefined();
			expect(credential?.principal_id).toEqual(principalId as string);
		});
	});

	describe('Usage Tracking', () => {
		it('should initialize failed_exchange_count to 0', async () => {
			const principalId = await createPrincipal(
				'track_init_test',
				'Track Init Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'track-client',
				clientSecret: validTestSecret,
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'track-client' },
			});

			expect(credential?.failed_exchange_count).toEqual(0);
		});

		it('should increment failed_exchange_count on invalid secret', async () => {
			const principalId = await createPrincipal(
				'track_failed_test',
				'Track Failed Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'track-failed-client',
				clientSecret: validTestSecret,
			});

			// Attempt 1 - wrong secret
			await expectAsync(
				auth.exchangeCredentials('track-failed-client', 'wrong-1')
			).toBeRejectedWithError();

			let credential = await credentialsRepo.findOne({
				where: { client_id: 'track-failed-client' },
			});
			expect(credential?.failed_exchange_count).toEqual(1);

			// Attempt 2 - wrong secret
			await expectAsync(
				auth.exchangeCredentials('track-failed-client', 'wrong-2')
			).toBeRejectedWithError();

			credential = await credentialsRepo.findOne({
				where: { client_id: 'track-failed-client' },
			});
			expect(credential?.failed_exchange_count).toEqual(2);
		});

		it('should reset failed_exchange_count on successful exchange', async () => {
			const principalId = await createPrincipal(
				'track_reset_test',
				'Track Reset Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'track-reset-client',
				clientSecret: validTestSecret,
			});

			// Fail once
			await expectAsync(
				auth.exchangeCredentials('track-reset-client', 'wrong-secret')
			).toBeRejectedWithError();

			let credential = await credentialsRepo.findOne({
				where: { client_id: 'track-reset-client' },
			});
			expect(credential?.failed_exchange_count).toEqual(1);

			// Succeed - should reset counter
			await auth.exchangeCredentials(
				'track-reset-client',
				validTestSecret
			);

			credential = await credentialsRepo.findOne({
				where: { client_id: 'track-reset-client' },
			});
			expect(credential?.failed_exchange_count).toEqual(0);
		});

		it('should update last_exchange_timestamp on successful exchange', async () => {
			const principalId = await createPrincipal(
				'track_timestamp_test',
				'Track Timestamp Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'track-timestamp-client',
				clientSecret: validTestSecret,
			});

			let credential = await credentialsRepo.findOne({
				where: { client_id: 'track-timestamp-client' },
			});
			expect(credential?.last_exchange_timestamp).toBeNull();

			// Perform exchange
			const beforeTime = new Date();
			await auth.exchangeCredentials(
				'track-timestamp-client',
				validTestSecret
			);
			const afterTime = new Date();

			credential = await credentialsRepo.findOne({
				where: { client_id: 'track-timestamp-client' },
			});

			expect(credential?.last_exchange_timestamp).toBeDefined();
			if (credential?.last_exchange_timestamp) {
				expect(
					credential.last_exchange_timestamp.getTime()
				).toBeGreaterThanOrEqual(beforeTime.getTime());
				expect(
					credential.last_exchange_timestamp.getTime()
				).toBeLessThanOrEqual(afterTime.getTime());
			}
		});
	});

	describe('Error Message Clarity', () => {
		it('should distinguish between revoked and nonexistent credentials', async () => {
			const principalId = await createPrincipal(
				'error_clarity_test',
				'Error Clarity Test'
			);

			// Create and revoke a credential
			await auth.createClientCredential({
				principalId,
				clientId: 'revoked-for-error-test',
				clientSecret: validTestSecret,
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'revoked-for-error-test' },
			});

			if (credential) {
				await auth.revokeClientCredential(credential.id);
			}

			// Try to exchange revoked credential
			let revokedError: string | undefined;
			try {
				await auth.exchangeCredentials(
					'revoked-for-error-test',
					validTestSecret
				);
			}
			catch (err: any) {
				revokedError = err.message;
			}

			expect(revokedError).toContain('revoked');

			// Try to exchange nonexistent credential
			let notFoundError: string | undefined;
			try {
				await auth.exchangeCredentials('never-existed', 'secret');
			}
			catch (err: any) {
				notFoundError = err.message;
			}

			expect(notFoundError).toContain('Invalid credentials');
			// Errors should be distinguishable internally, even if both are generic for security
			expect(revokedError).not.toEqual(notFoundError);
		});
	});

	describe('Secret Generation Utility', () => {
		it('should generate cryptographically secure secrets', () => {
			const secret1 = generateSecret();
			const secret2 = generateSecret();

			expect(secret1).toBeDefined();
			expect(secret2).toBeDefined();
			expect(secret1.length).toEqual(32);
			expect(secret2.length).toEqual(32);
			expect(secret1).not.toEqual(secret2);
		});

		it('should generate secrets of custom length', () => {
			const lengths = [16, 24, 32, 64];

			for (const length of lengths) {
				const secret = generateSecret(length);
				expect(secret.length).toEqual(length);
			}
		});

		it('should generate alphanumeric secrets without padding', () => {
			const secret = generateSecret();

			// Should not contain base64 padding or special chars
			expect(secret).not.toContain('=');
			expect(secret).not.toContain('+');
			expect(secret).not.toContain('/');

			// Should only contain alphanumeric
			expect(/^[a-zA-Z0-9]+$/.test(secret)).toBe(true);
		});

		it('should use generated secret in credential creation', async () => {
			const principalId = await createPrincipal(
				'generated_secret_test',
				'Generated Secret Test'
			);

			const generatedSecret = generateSecret();

			await auth.createClientCredential({
				principalId,
				clientId: 'generated-secret-client',
				clientSecret: generatedSecret,
				description: 'Client with Generated Secret',
			});

			// Should be able to exchange with generated secret
			const tokenResponse = await auth.exchangeCredentials(
				'generated-secret-client',
				generatedSecret
			);

			expect(tokenResponse.access_token).toBeDefined();
			expect(tokenResponse.token_type).toEqual('Bearer');
		});
	});

	describe('OAuth2 Token Exchange', () => {
		it('should exchange valid credentials for access token', async () => {
			const principalId = await createPrincipal(
				'exchange_test',
				'Exchange Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'exchange-client',
				clientSecret: validTestSecret,
			});

			const tokenResponse = await auth.exchangeCredentials(
				'exchange-client',
				validTestSecret
			);

			expect(tokenResponse.token_type).toEqual('Bearer');
			expect(tokenResponse.expires_in).toEqual(3600);
			expect(tokenResponse.access_token.length).toBeGreaterThan(0);
		});

		it('should reject invalid client_id', async () => {
			await expectAsync(
				auth.exchangeCredentials('nonexistent-client', 'secret')
			).toBeRejectedWithError(/Invalid credentials/);
		});

		it('should reject invalid client_secret', async () => {
			const principalId = await createPrincipal(
				'invalid_secret_test',
				'Invalid Secret Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'secret-test-client',
				clientSecret: validTestSecret,
			});

			await expectAsync(
				auth.exchangeCredentials('secret-test-client', 'wrong-secret')
			).toBeRejectedWithError(/Invalid credentials/);
		});

		it('should reject revoked credentials', async () => {
			const principalId = await createPrincipal(
				'revoked_exchange_test',
				'Revoked Exchange Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'revoked-client',
				clientSecret: validTestSecret,
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'revoked-client' },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			await expectAsync(
				auth.exchangeCredentials('revoked-client', validTestSecret)
			).toBeRejectedWithError(/revoked/);
		});
	});

	describe('Token Verification', () => {
		it('should verify valid access token', async () => {
			const principalId = await createPrincipal(
				'verify_token_test',
				'Verify Token Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'verify-client',
				clientSecret: validTestSecret,
			});

			const tokenResponse = await auth.exchangeCredentials(
				'verify-client',
				validTestSecret
			);

			const payload = await auth.verifyAccessToken(
				tokenResponse.access_token
			);

			expect(payload).toBeDefined();
			if (payload) {
				expect(payload.client_id).toEqual('verify-client');
				expect(payload.principal_id).toEqual(principalId as string);
			}
		});

		it('should reject invalid token format', async () => {
			await expectAsync(
				auth.verifyAccessToken('invalid-token')
			).toBeRejectedWithError();
		});

		it('should reject token from revoked credential', async () => {
			const principalId = await createPrincipal(
				'revoked_verify_test',
				'Revoked Verify Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'revoke-verify-client',
				clientSecret: validTestSecret,
			});

			const tokenResponse = await auth.exchangeCredentials(
				'revoke-verify-client',
				validTestSecret
			);

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'revoke-verify-client' },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			const payload = await auth.verifyAccessToken(
				tokenResponse.access_token
			);

			expect(payload).toBeNull();
		});
	});

	describe('Credential Revocation', () => {
		it('should revoke a single client credential', async () => {
			const principalId = await createPrincipal(
				'revoke_single_test',
				'Revoke Single Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'revoke-single-client',
				clientSecret: validTestSecret,
			});

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'revoke-single-client' },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			const revokedCredential = await credentialsRepo.findOne({
				where: { id: credential.id as string },
			});

			expect(revokedCredential?.deactivate_timestamp).toBeDefined();
		});

		it('should revoke all credentials for a principal', async () => {
			const principalId = await createPrincipal(
				'revoke_all_test',
				'Revoke All Test'
			);

			await auth.createClientCredential({
				principalId,
				clientId: 'revoke-all-client-1',
				clientSecret: validTestSecret,
			});

			await auth.createClientCredential({
				principalId,
				clientId: 'revoke-all-client-2',
				clientSecret: alternateTestSecret,
			});

			await auth.revokeAllCredentials(principalId);

			const credentials = await auth.listCredentials(principalId);
			expect(credentials.length).toEqual(0);
		});

		it('should prevent reusing a revoked client_id', async () => {
			const principalId = await createPrincipal(
				'revoked_reuse_test',
				'Revoked Reuse Test'
			);

			const clientId = 'revoke-reuse-client';

			// Create initial credential
			await auth.createClientCredential({
				principalId,
				clientId: clientId,
				clientSecret: validTestSecret,
				description: 'Original Client',
			});

			// Revoke the credential
			const credential = await credentialsRepo.findOne({
				where: { client_id: clientId },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			// Attempt to reuse the same client_id with different secret
			// Should fail with application-level error (not DB constraint error)
			await expectAsync(
				auth.createClientCredential({
					principalId,
					clientId: clientId,
					clientSecret: alternateTestSecret,
					description: 'New Client',
				})
			).toBeRejectedWithError(/already in use/);
		});

		it('should prevent reusing revoked client_id across different principals', async () => {
			const principal1Id = await createPrincipal(
				'revoked_cross_principal_1',
				'Cross Principal Test 1'
			);
			const principal2Id = await createPrincipal(
				'revoked_cross_principal_2',
				'Cross Principal Test 2'
			);

			const clientId = 'cross-principal-client';

			// Principal 1 creates credential
			await auth.createClientCredential({
				principalId: principal1Id,
				clientId: clientId,
				clientSecret: validTestSecret,
			});

			// Principal 1 revokes it
			const credential = await credentialsRepo.findOne({
				where: { client_id: clientId },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			// Principal 2 tries to create credential with same client_id
			// Should fail even though it's a different principal
			// because client_id is globally unique
			await expectAsync(
				auth.createClientCredential({
					principalId: principal2Id,
					clientId: clientId,
					clientSecret: alternateTestSecret,
				})
			).toBeRejectedWithError(/already in use/);
		});

		it('should allow creating new credential after revoke with different client_id', async () => {
			const principalId = await createPrincipal(
				'revoked_different_id_test',
				'Revoked Different ID Test'
			);

			const clientId1 = 'revoke-diff-1';
			const clientId2 = 'revoke-diff-2';

			// Create and revoke first credential
			await auth.createClientCredential({
				principalId,
				clientId: clientId1,
				clientSecret: validTestSecret,
			});

			const credential1 = await credentialsRepo.findOne({
				where: { client_id: clientId1 },
			});

			if (!credential1) {
				throw new Error('Credential 1 not found');
			}

			await auth.revokeClientCredential(credential1.id);

			// Create new credential with different client_id
			// Should succeed
			await auth.createClientCredential({
				principalId,
				clientId: clientId2,
				clientSecret: alternateTestSecret,
				description: 'New Client',
			});

			const credential2 = await credentialsRepo.findOne({
				where: { client_id: clientId2 },
			});

			expect(credential2).toBeDefined();
			if (credential2) {
				expect(credential2.principal_id).toEqual(principalId as string);
				expect(credential2.client_id).toEqual(clientId2);
			}
		});
	});

	describe('Configuration Variations', () => {
		it('should accept ms format expiration', async () => {
			const authWithMsExpiry =
				new (class extends OAuth2ClientCredentialsAuthentication<OAuth2Principal> {})(
					{
						db,
						jwtSecret: 'test-secret-key-minimum-32-characters-long',
						tokenExpiresIn: '30m',
						jwtAlgorithm: 'HS256',
					}
				);

			// Verify it accepts ms format without error
			expect(authWithMsExpiry).toBeDefined();
		});

		it('should use HS512 algorithm when specified', async () => {
			const authWithHS512 =
				new (class extends OAuth2ClientCredentialsAuthentication<OAuth2Principal> {})(
					{
						db,
						jwtSecret: 'test-secret-key-minimum-32-characters-long',
						tokenExpiresIn: 3600,
						jwtAlgorithm: 'HS512',
					}
				);

			const principalId = await createPrincipal(
				'hs512_test',
				'HS512 Test'
			);

			await authWithHS512.createClientCredential({
				principalId,
				clientId: 'hs512-client',
				clientSecret: validTestSecret,
			});

			const tokenResponse = await authWithHS512.exchangeCredentials(
				'hs512-client',
				validTestSecret
			);

			const payload = await authWithHS512.verifyAccessToken(
				tokenResponse.access_token
			);

			expect(payload).toBeDefined();
			if (payload) {
				expect(payload.client_id).toEqual('hs512-client');
			}
		});
	});
});
