import { Database, DatabaseRecord, QueryRepository } from '@riao/dbal';
import { Hash, Jwt } from '@riao/crypto';
import { Principal } from '@riao/iam/auth';
import {
	OAuth2ClientCredentialsAuthentication,
	OAuth2ClientCredentialsOptions,
} from '../../src/oauth2-client-credentials-authentication';

describe('OAuth2 issuer and audience', () => {
	const secret = 'claim-scoping-test-secret-at-least-32-characters';
	let db: jasmine.SpyObj<Database>;
	let repo: jasmine.SpyObj<QueryRepository<DatabaseRecord>>;
	let hash: Hash;
	let auth: OAuth2ClientCredentialsAuthentication<Principal>;

	function create(options: Partial<OAuth2ClientCredentialsOptions> = {}) {
		return new (class extends
			OAuth2ClientCredentialsAuthentication<Principal> {})({
			db, hash, jwtSecret: secret, jwtAlgorithm: 'HS256', ...options,
		});
	}

	beforeEach(() => {
		db = jasmine.createSpyObj<Database>('db', ['getQueryRepository']);
		repo = jasmine.createSpyObj('repo', ['findOne', 'update']);
		db.getQueryRepository.and.returnValue(repo);
		repo.findOne.and.resolveTo({
			id: 'credential', client_id: 'client', principal_id: 'user',
			client_secret_hash: 'hash', deactivate_timestamp: null,
		});
		repo.update.and.resolveTo();
		hash = new Hash();
		spyOn(hash, 'check').and.resolveTo(true);
		auth = create({ jwtIssuer: 'issuer', jwtAudience: 'api' });
		spyOn(auth, 'findActivePrincipal').and.resolveTo({
			id: 'user', login: 'user', name: 'User', type: 'service',
			create_timestamp: new Date(),
		});
	});

	it('issues claims accepted by its configured verifier', async () => {
		const response = await auth.exchangeCredentials('client', 'secret');
		const payload = await auth.verifyAccessToken(response.access_token);
		expect(payload).toEqual(
			jasmine.objectContaining({ iss: 'issuer', aud: 'api' })
		);
	});

	it('rejects invalid claims before storage lookups', async () => {
		const jwt = new Jwt({ secret, algorithm: 'HS256' });
		for (const options of [
			{}, { issuer: 'other', audience: 'api' },
			{ issuer: 'issuer', audience: 'other' },
			{ issuer: 'issuer' }, { audience: 'api' },
		]) {
			const signed = await jwt.generateToken({
				client_id: 'client', principal_id: 'user',
				token_type: 'access',
			}, options);
			expect(await auth.verifyAccessToken(signed.token)).toBeNull();
		}
		expect(repo.findOne).not.toHaveBeenCalled();
	});

	it('preserves unconfigured issuance and verification', async () => {
		const unconfigured = create();
		spyOn(unconfigured, 'findActivePrincipal').and.resolveTo({
			id: 'user', login: 'user', name: 'User', type: 'service',
			create_timestamp: new Date(),
		});
		const response = await unconfigured.exchangeCredentials(
			'client', 'secret'
		);
		const payload = await unconfigured.verifyAccessToken(
			response.access_token
		);
		expect(payload).toEqual(
			jasmine.objectContaining({
				client_id: 'client', principal_id: 'user',
			})
		);
	});

	it('rejects empty configuration', () => {
		for (const options of [
			{ jwtIssuer: '' }, { jwtIssuer: ' ' },
			{ jwtAudience: '' }, { jwtAudience: ' ' },
		]) {
			expect(() => create(options)).toThrowError(
				'JWT issuer and audience must be non-empty'
			);
		}
	});
});
