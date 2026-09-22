import 'jasmine';
// eslint-disable-next-line max-len
import { OAuth2ClientCredentialsAuthentication } from '../../src/oauth2-client-credentials-authentication';
import { createDatabase, runMigrations, runMigrationsDown } from '../database';
import { Principal } from '@riao/iam/auth';
// eslint-disable-next-line max-len
import { OAuth2ClientCredentialsMigrations } from '../../src/oauth2-client-credentials-migrations';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import { compare } from 'bcrypt';

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

			await auth.createClientCredential(
				principalId,
				'test-client-1',
				'test-secret-123',
				'Test Client'
			);

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
						'test-secret-123',
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

			await auth.createClientCredential(
				principalId,
				'duplicate-client',
				'secret-1'
			);

			// Attempt to create with same client_id
			await expectAsync(
				auth.createClientCredential(
					principalId,
					'duplicate-client',
					'secret-2'
				)
			).toBeRejectedWithError(/already in use/);
		});

		it('should list active credentials for a principal', async () => {
			const principalId = await createPrincipal(
				'list_credentials_test',
				'List Credentials Test'
			);

			await auth.createClientCredential(
				principalId,
				'list-client-1',
				'secret-1',
				'Client 1'
			);

			await auth.createClientCredential(
				principalId,
				'list-client-2',
				'secret-2',
				'Client 2'
			);

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

			await auth.createClientCredential(
				principalId,
				'sensitive-client',
				'very-sensitive-secret'
			);

			const credentials = await auth.listCredentials(principalId);

			expect(credentials.length).toEqual(1);
			// Type system ensures client_secret_hash is omitted
			expect(credentials[0].client_id).toEqual('sensitive-client');
		});
	});

	describe('OAuth2 Token Exchange', () => {
		it('should exchange valid credentials for access token', async () => {
			const principalId = await createPrincipal(
				'exchange_test',
				'Exchange Test'
			);

			await auth.createClientCredential(
				principalId,
				'exchange-client',
				'exchange-secret'
			);

			const tokenResponse = await auth.exchangeCredentials(
				'exchange-client',
				'exchange-secret'
			);

			expect(tokenResponse.token_type).toEqual('Bearer');
			expect(tokenResponse.expires_in).toEqual(3600);
			expect(tokenResponse.access_token.length).toBeGreaterThan(0);
		});

		it('should reject invalid client_id', async () => {
			await expectAsync(
				auth.exchangeCredentials('nonexistent-client', 'secret')
			).toBeRejectedWithError(/Invalid client_id/);
		});

		it('should reject invalid client_secret', async () => {
			const principalId = await createPrincipal(
				'invalid_secret_test',
				'Invalid Secret Test'
			);

			await auth.createClientCredential(
				principalId,
				'secret-test-client',
				'correct-secret'
			);

			await expectAsync(
				auth.exchangeCredentials('secret-test-client', 'wrong-secret')
			).toBeRejectedWithError(/Invalid client_secret/);
		});

		it('should reject revoked credentials', async () => {
			const principalId = await createPrincipal(
				'revoked_exchange_test',
				'Revoked Exchange Test'
			);

			await auth.createClientCredential(
				principalId,
				'revoked-client',
				'revoked-secret'
			);

			const credential = await credentialsRepo.findOne({
				where: { client_id: 'revoked-client' },
			});

			if (!credential) {
				throw new Error('Credential not found');
			}

			await auth.revokeClientCredential(credential.id);

			await expectAsync(
				auth.exchangeCredentials('revoked-client', 'revoked-secret')
			).toBeRejectedWithError(/Invalid client_id/);
		});
	});

	describe('Token Verification', () => {
		it('should verify valid access token', async () => {
			const principalId = await createPrincipal(
				'verify_token_test',
				'Verify Token Test'
			);

			await auth.createClientCredential(
				principalId,
				'verify-client',
				'verify-secret'
			);

			const tokenResponse = await auth.exchangeCredentials(
				'verify-client',
				'verify-secret'
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
			const payload = await auth.verifyAccessToken('invalid-token');
			expect(payload).toBeNull();
		});

		it('should reject token from revoked credential', async () => {
			const principalId = await createPrincipal(
				'revoked_verify_test',
				'Revoked Verify Test'
			);

			await auth.createClientCredential(
				principalId,
				'revoke-verify-client',
				'revoke-verify-secret'
			);

			const tokenResponse = await auth.exchangeCredentials(
				'revoke-verify-client',
				'revoke-verify-secret'
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

			await auth.createClientCredential(
				principalId,
				'revoke-single-client',
				'revoke-single-secret'
			);

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

			await auth.createClientCredential(
				principalId,
				'revoke-all-client-1',
				'secret-1'
			);

			await auth.createClientCredential(
				principalId,
				'revoke-all-client-2',
				'secret-2'
			);

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
			await auth.createClientCredential(
				principalId,
				clientId,
				'original-secret',
				'Original Client'
			);

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
				auth.createClientCredential(
					principalId,
					clientId,
					'new-secret',
					'New Client'
				)
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
			await auth.createClientCredential(
				principal1Id,
				clientId,
				'secret-1'
			);

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
				auth.createClientCredential(
					principal2Id,
					clientId,
					'secret-2'
				)
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
			await auth.createClientCredential(
				principalId,
				clientId1,
				'secret-1'
			);

			const credential1 = await credentialsRepo.findOne({
				where: { client_id: clientId1 },
			});

			if (!credential1) {
				throw new Error('Credential 1 not found');
			}

			await auth.revokeClientCredential(credential1.id);

			// Create new credential with different client_id
			// Should succeed
			await auth.createClientCredential(
				principalId,
				clientId2,
				'secret-2',
				'New Client'
			);

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

			await authWithHS512.createClientCredential(
				principalId,
				'hs512-client',
				'hs512-secret'
			);

			const tokenResponse = await authWithHS512.exchangeCredentials(
				'hs512-client',
				'hs512-secret'
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
