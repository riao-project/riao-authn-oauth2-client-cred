import { Database, DatabaseRecord, QueryRepository } from '@riao/dbal';
import { Hash, Jwt } from '@riao/crypto';
import { Principal } from '@riao/iam/auth';
import {
	OAuth2ClientCredentialsAuthentication,
} from '../../src/oauth2-client-credentials-authentication';

describe('OAuth2 access-token purpose', () => {
	const secret = 'token-purpose-test-secret-at-least-32-characters';
	let repo: jasmine.SpyObj<QueryRepository<DatabaseRecord>>;
	let auth: OAuth2ClientCredentialsAuthentication<Principal>;

	beforeEach(() => {
		const db = jasmine.createSpyObj<Database>('db', ['getQueryRepository']);
		repo = jasmine.createSpyObj('repo', ['findOne', 'update']);
		db.getQueryRepository.and.returnValue(repo);
		repo.findOne.and.resolveTo({
			id: 'credential', client_id: 'client', principal_id: 'user',
			client_secret_hash: 'hash', deactivate_timestamp: null,
		});
		repo.update.and.resolveTo();
		const hash = new Hash();
		spyOn(hash, 'check').and.resolveTo(true);
		auth = new (class extends
			OAuth2ClientCredentialsAuthentication<Principal> {})({
			db, hash, jwtSecret: secret, jwtAlgorithm: 'HS256',
		});
		spyOn(auth, 'findActivePrincipal').and.resolveTo({
			id: 'user', login: 'user', name: 'User', type: 'service',
			create_timestamp: new Date(),
		});
	});

	it('issues access purpose and retains Bearer transport', async () => {
		const response = await auth.exchangeCredentials('client', 'secret');
		expect(response.token_type).toBe('Bearer');
		const payload = await auth.verifyAccessToken(response.access_token);
		expect(payload).toEqual(
			jasmine.objectContaining({ token_type: 'access' })
		);
	});

	it('rejects legacy, wrong-purpose, and malformed claims', async () => {
		const jwt = new Jwt({ secret, algorithm: 'HS256' });
		for (const claims of [
			{},
			{ token_type: 'refresh' },
			{ token_type: 'access', client_id: '' },
			{ token_type: 'access', client_id: ' ' },
			{ token_type: 'access', client_id: 1 },
			{ token_type: 'access', principal_id: '' },
			{ token_type: 'access', principal_id: ' ' },
			{ token_type: 'access', principal_id: 1 },
		]) {
			const signed = await jwt.generateToken({
				client_id: 'client', principal_id: 'user', ...claims,
			});
			expect(await auth.verifyAccessToken(signed.token)).toBeNull();
		}
		expect(repo.findOne).not.toHaveBeenCalled();
	});

	it('still rejects revoked credentials', async () => {
		repo.findOne.and.resolveTo(null);
		const jwt = new Jwt({ secret, algorithm: 'HS256' });
		const signed = await jwt.generateToken({
			client_id: 'client', principal_id: 'user', token_type: 'access',
		});
		expect(await auth.verifyAccessToken(signed.token)).toBeNull();
		expect(auth.findActivePrincipal).not.toHaveBeenCalled();
	});
});
