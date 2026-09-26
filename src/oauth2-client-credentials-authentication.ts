/**
 * OAuth2 Client Credentials Authentication
 */
import { Jwt, JwtPayload } from '@riao/crypto';
import ms from 'ms';
import { DatabaseRecordId, QueryRepository } from '@riao/dbal';
import { Hash } from '@riao/iam/hash';
import { Principal } from '@riao/iam/auth';
import { Authentication } from '@riao/iam/authentication';
import { AuthOptions } from '@riao/iam/auth/auth';
import {
	ClientCredential,
	CLIENT_ID_VALIDATION,
	CLIENT_SECRET_VALIDATION,
} from './client-credential';

/**
 * OAuth2 Client Credentials Token Payload
 */
export interface OAuth2TokenPayload extends JwtPayload {
	client_id: string;
	principal_id: string;
}

export interface OAuth2ClientCredentialsOptions extends AuthOptions {
	hash?: Hash;
	/**
	 * JWT secret for signing tokens
	 * In production: use strong, random 32+ character secret
	 */
	jwtSecret: string;
	/**
	 * Token expiration time
	 * Can be ms format string ("1h", "30m", "7d") or numeric seconds
	 * Default: "1h" (1 hour)
	 */
	tokenExpiresIn?: ms.StringValue | number;
	/**
	 * JWT algorithm for signing
	 * Default: HS256
	 */
	jwtAlgorithm?: 'HS256' | 'HS512';
}

/**
 * OAuth2 Client Credentials Authentication
 * Implements server-to-server authentication using client_id and client_secret
 *
 * Features:
 * - Client credential management with bcrypt hashing
 * - JWT token generation with configurable expiration
 * - Token validation and verification
 * - Multiple credentials per principal
 * - Credential revocation support
 */
export abstract class OAuth2ClientCredentialsAuthentication<
	TPrincipal extends Principal,
> extends Authentication<TPrincipal> {
	public credentialsRepo: QueryRepository<ClientCredential>;
	protected hash: Hash;
	protected jwt: Jwt<OAuth2TokenPayload>;
	protected tokenExpiresInMs: ms.StringValue;
	protected tokenExpiresInSeconds: number;

	public constructor(options: OAuth2ClientCredentialsOptions) {
		super(options);
		this.hash = options.hash ?? new Hash();

		// Convert tokenExpiresIn to ms format and seconds
		const expiresIn = options.tokenExpiresIn ?? '1h';
		this.tokenExpiresInMs =
			typeof expiresIn === 'number' ? `${expiresIn}s` : expiresIn;
		this.tokenExpiresInSeconds =
			typeof expiresIn === 'number'
				? expiresIn
				: (ms(expiresIn) as number) / 1000;

		// Initialize JWT handler
		this.jwt = new Jwt<OAuth2TokenPayload>({
			secret: options.jwtSecret,
			expiresIn: this.tokenExpiresInMs,
			algorithm: (options.jwtAlgorithm ?? 'HS256') as 'HS256' | 'HS512',
		});

		this.credentialsRepo = options.db.getQueryRepository<ClientCredential>({
			table: 'oauth2_client_credentials',
			identifiedBy: 'id',
		});
	}

	/**
	 * Validate client_id format
	 * @param clientId Client identifier to validate
	 * @throws Error if format is invalid
	 */
	private validateClientId(clientId: string): void {
		if (!clientId || clientId.length < CLIENT_ID_VALIDATION.MIN_LENGTH) {
			throw new Error(
				`Client ID must be at least ${CLIENT_ID_VALIDATION.MIN_LENGTH} characters`
			);
		}

		if (clientId.length > CLIENT_ID_VALIDATION.MAX_LENGTH) {
			throw new Error(
				`Client ID cannot exceed ${CLIENT_ID_VALIDATION.MAX_LENGTH} characters`
			);
		}

		if (!CLIENT_ID_VALIDATION.PATTERN.test(clientId)) {
			throw new Error(
				'Client ID must contain only alphanumeric characters, hyphens, underscores, dots, and colons'
			);
		}
	}

	/**
	 * Create a new client credential for a principal
	 * @param principalId The principal ID
	 * @param clientId Unique client identifier
	 * @param clientSecret Secret (will be hashed before storage)
	 * @param description Optional description
	 * @throws Error if principal doesn't exist, client_id is invalid, or already in use
	 */
	public async createClientCredential(
		principalId: DatabaseRecordId,
		clientId: string,
		clientSecret: string,
		description?: string
	): Promise<void> {
		// Validate client_id format
		this.validateClientId(clientId);
		if (clientSecret.length < CLIENT_SECRET_VALIDATION.MIN_LENGTH) {
			throw new Error(
				`Client secret must be at least ${CLIENT_SECRET_VALIDATION.MIN_LENGTH} characters`
			);
		}

		// Verify principal exists
		const principal = await this.findActivePrincipal({
			where: { id: principalId } as TPrincipal,
		});

		if (!principal) {
			throw new Error(
				`Principal with ID "${principalId}" does not exist or is inactive`
			);
		}

		// Hash the client secret
		const secretHash = await this.hash.make(clientSecret);

		// Check if client_id is already in use (active or revoked)
		// The DB has a global unique constraint on client_id, so we must
		// check all records to avoid unique constraint violations
		const existing = await this.credentialsRepo.findOne({
			where: { client_id: clientId },
		});

		if (existing) {
			throw new Error(`Client ID "${clientId}" is already in use`);
		}

		// Store credential
		await this.credentialsRepo.insertOne({
			record: {
				principal_id: principalId as string,
				client_id: clientId,
				client_secret_hash: secretHash,
				description: description ?? null,
				create_timestamp: new Date(),
				failed_exchange_count: 0,
			},
		});
	}

	/**
	 * Exchange client credentials for an access token
	 * Implements OAuth2 Client Credentials grant
	 *
	 * @param clientId Client identifier
	 * @param clientSecret Client secret
	 * @returns Access token and expiration info
	 * @throws Error if credentials are invalid or principal not found
	 */
	public async exchangeCredentials(
		clientId: string,
		clientSecret: string
	): Promise<{
		access_token: string;
		token_type: 'Bearer';
		expires_in: number;
	}> {
		// Find credential by client_id (active or revoked)
		const credential = await this.credentialsRepo.findOne({
			where: { client_id: clientId },
		});

		// Distinguish between credential not found vs. revoked
		if (!credential) {
			throw new Error('Invalid credentials');
		}

		if (credential.deactivate_timestamp !== null) {
			throw new Error('Credential has been revoked');
		}

		// Verify secret and track failed attempts
		const isValid = await this.hash.check(
			clientSecret,
			credential.client_secret_hash
		);

		if (!isValid) {
			// Increment failed attempt counter
			await this.credentialsRepo.update({
				set: {
					failed_exchange_count:
						(credential.failed_exchange_count || 0) + 1,
				},
				where: { id: credential.id },
			});

			throw new Error('Invalid credentials');
		}

		// Get principal details
		const principal = await this.findActivePrincipal({
			where: { id: credential.principal_id } as TPrincipal,
		});

		if (!principal) {
			throw new Error('Principal not found');
		}

		// Generate JWT token using @riao/crypto
		const payload: OAuth2TokenPayload = {
			client_id: clientId,
			principal_id: credential.principal_id,
		};

		const tokenResult = await this.jwt.generateToken(payload);

		// Update last exchange timestamp and reset failed attempts on success
		await this.credentialsRepo.update({
			set: {
				last_exchange_timestamp: new Date(),
				failed_exchange_count: 0,
			},
			where: { id: credential.id },
		});

		return {
			access_token: tokenResult.token,
			token_type: 'Bearer',
			expires_in: this.tokenExpiresInSeconds,
		};
	}

	/**
	 * Verify and decode an access token
	 * @param token JWT access token
	 * @returns Token payload if valid, null if invalid or expired
	 */
	public async verifyAccessToken(
		token: string
	): Promise<OAuth2TokenPayload | null> {
		const payload = await this.jwt.decodeToken(token);

		// Verify credential is still active
		const credential = await this.credentialsRepo.findOne({
			where: {
				client_id: payload.client_id,
				deactivate_timestamp: null,
			},
		});

		if (!credential) {
			return null;
		}

		return payload;
	}

	/**
	 * Revoke a client credential
	 * Prevents future token generation with this credential
	 * @param credentialId The credential ID to revoke
	 */
	public async revokeClientCredential(
		credentialId: DatabaseRecordId
	): Promise<void> {
		await this.credentialsRepo.update({
			set: { deactivate_timestamp: new Date() },
			where: {
				id: credentialId as string,
			},
		});
	}

	/**
	 * Revoke all credentials for a principal
	 * @param principalId The principal ID
	 */
	public async revokeAllCredentials(
		principalId: DatabaseRecordId
	): Promise<void> {
		await this.credentialsRepo.update({
			set: { deactivate_timestamp: new Date() },
			where: {
				principal_id: principalId as string,
				deactivate_timestamp: null,
			},
		});
	}

	/**
	 * List all active credentials for a principal
	 * @param principalId The principal ID
	 * @returns Array of credentials (without secret hashes)
	 */
	public async listCredentials(
		principalId: DatabaseRecordId
	): Promise<Omit<ClientCredential, 'client_secret_hash'>[]> {
		const credentials = await this.credentialsRepo.find({
			where: {
				principal_id: principalId as string,
				deactivate_timestamp: null,
			},
		});

		// Remove sensitive hashes before returning
		return credentials.map(
			({ client_secret_hash, ...safe }) =>
				safe as Omit<ClientCredential, 'client_secret_hash'>
		);
	}

	/**
	 * Authenticate using OAuth2 token
	 * (For compatibility with Authentication interface)
	 */
	public async authenticate(
		credentials: Partial<
			TPrincipal & { client_id: string; client_secret: string }
		>
	): Promise<TPrincipal | null> {
		const token = await this.exchangeCredentials(
				credentials.client_id as string,
				credentials.client_secret as string
		);

		const payload = await this.verifyAccessToken(token.access_token);

		if (!payload) {
			return null;
		}

		const principal = await this.findActivePrincipal({
			where: { id: payload.principal_id } as TPrincipal,
		});

		return principal;
	}
}
