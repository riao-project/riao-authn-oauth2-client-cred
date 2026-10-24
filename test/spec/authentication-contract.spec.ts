import { Database } from '@riao/dbal';
import { Hash, Jwt } from '@riao/crypto';
import { Principal } from '@riao/iam/auth';
import {
	AuthenticationProtection,
	AuthenticationBlockedError,
	AuthenticationRejectedError,
} from '@riao/iam/authentication';
import {
	OAuth2ClientCredentialsAuthentication,
	OAuth2TokenPayload,
} from '../../src/oauth2-client-credentials-authentication';

describe('OAuth2 authentication contract', () => {
	const secret = 'oauth2-contract-test-secret-at-least-32-characters';
	let auth: OAuth2ClientCredentialsAuthentication<Principal>;
	let protection: jasmine.SpyObj<AuthenticationProtection>;
	let principal: Principal;
	let jwt: Jwt<OAuth2TokenPayload>;

	beforeEach(() => {
		const db = jasmine.createSpyObj<Database>('db', ['getQueryRepository']);
		const repo = jasmine.createSpyObj('repo', ['findOne', 'update']);
		db.getQueryRepository.and.returnValue(repo);
		protection = jasmine.createSpyObj<AuthenticationProtection>(
			'protection', ['beforeAttempt', 'onFailure', 'onSuccess']
		);
		protection.beforeAttempt.and.resolveTo({ allowed: true });
		protection.onFailure.and.resolveTo();
		protection.onSuccess.and.resolveTo();
		const hash = new Hash();
		spyOn(hash, 'check').and.resolveTo(true);
		auth = new (class extends
			OAuth2ClientCredentialsAuthentication<Principal> {})({
			db, hash, jwtSecret: secret, jwtAlgorithm: 'HS256',
			authenticationProtection: protection,
		});
		principal = {
			id: 'user', login: 'user', name: 'User', type: 'service',
			create_timestamp: new Date(),
		};
		spyOn(auth, 'findActivePrincipal').and.resolveTo(principal);
		repo.findOne.and.resolveTo({
			id: 'credential', client_id: 'client', principal_id: principal.id,
			client_secret_hash: 'hash', deactivate_timestamp: null,
		});
		repo.update.and.resolveTo();
		jwt = new Jwt({ secret, algorithm: 'HS256' });
	});

	async function token() {
		return (await jwt.generateToken({
			client_id: 'client', principal_id: 'user',
		})).token;
	}

	it('issues tokens accepted by verification', async () => {
		protection.onSuccess.and.callFake(async () => {
			expect(auth.credentialsRepo.update).toHaveBeenCalledTimes(1);
		});
		const response = await auth.exchangeCredentials('client', 'secret');
		expect(response.token_type).toBe('Bearer');
		expect(response.expires_in).toBe(3600);
		expect(await auth.verifyAccessToken(response.access_token))
			.toEqual(jasmine.objectContaining({
				client_id: 'client', principal_id: 'user',
			}));
		expect(protection.onSuccess).toHaveBeenCalledTimes(1);
	});

	it('rejects invalid tokens', async () => {
		expect(await auth.verifyAccessToken('invalid')).toBeNull();
	});

	it('rejects revoked credentials and inactive principals', async () => {
		(auth.credentialsRepo.findOne as jasmine.Spy).and.resolveTo(null);
		expect(await auth.verifyAccessToken(await token())).toBeNull();
		(auth.credentialsRepo.findOne as jasmine.Spy).and.resolveTo({
			id: 'credential',
		});
		(auth.findActivePrincipal as jasmine.Spy).and.resolveTo(null);
		expect(await auth.verifyAccessToken(await token())).toBeNull();
	});

	it('preserves block delays and null authentication', async () => {
		protection.beforeAttempt.and.resolveTo({
			allowed: false, retryAfterSeconds: 30,
		});
		await expectAsync(auth.exchangeCredentials('client', 'secret'))
			.toBeRejectedWith(jasmine.objectContaining({
				name: 'AuthenticationBlockedError', retryAfterSeconds: 30,
			}));
		expect(await auth.authenticate({
			client_id: 'client', client_secret: 'secret',
		})).toBeNull();
		expect(auth.credentialsRepo.findOne).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('uses typed rejection and records failures once', async () => {
		(auth.credentialsRepo.findOne as jasmine.Spy).and.resolveTo(null);
		await expectAsync(auth.exchangeCredentials('missing', 'secret'))
			.toBeRejectedWithError(AuthenticationRejectedError);
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(await auth.authenticate({
			client_id: 'missing', client_secret: 'secret',
		})).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(2);
		expect(protection.onSuccess).not.toHaveBeenCalled();
		expect(new AuthenticationBlockedError(1) instanceof
			AuthenticationRejectedError).toBe(true);
	});

	it('propagates store failures without recording', async () => {
		const error = new Error('Credential store unavailable');
		(auth.credentialsRepo.findOne as jasmine.Spy).and.rejectWith(error);
		await expectAsync(auth.verifyAccessToken(await token()))
			.toBeRejectedWith(error);
		await expectAsync(auth.authenticate({
			client_id: 'client', client_secret: 'secret',
		})).toBeRejectedWith(error);
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('propagates exchange persistence failures before recording success',
		async () => {
			const error = new Error('Credential persistence unavailable');
			(auth.credentialsRepo.update as jasmine.Spy).and.rejectWith(error);
			await expectAsync(
				auth.exchangeCredentials('client', 'secret')
			).toBeRejectedWith(error);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
		});
});
