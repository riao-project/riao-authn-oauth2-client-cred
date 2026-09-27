/**
 * OAuth2 Client Credential Record
 * Stored in database to track client credentials and their lifecycle
 */
import { randomBytes } from 'node:crypto';

export interface ClientCredential {
	id: string;
	principal_id: string;
	client_id: string;
	client_secret_hash: string;
	description?: string | null;
	create_timestamp: Date;
	deactivate_timestamp?: Date | null;
	last_exchange_timestamp?: Date | null;
	failed_exchange_count: number;
	locked_until?: Date | null;
}

/**
 * Client ID validation constraints
 */
export const CLIENT_ID_VALIDATION = {
	MIN_LENGTH: 3,
	MAX_LENGTH: 255,
	// Alphanumeric, hyphens, underscores, dots, colons
	PATTERN: /^[a-zA-Z0-9._:-]+$/,
} as const;

/**
 * Client secret validation constraints
 */
export const CLIENT_SECRET_VALIDATION = {
	MIN_LENGTH: 32,
} as const;

/**
 * Generate a cryptographically secure random secret
 * @param length Length of secret to generate (default: 32)
 * @returns Random hexadecimal secret of the requested length
 */
export function generateSecret(length: number = 32): string {
	const byteLength = Math.ceil(length / 2);

	return randomBytes(byteLength).toString('hex').slice(0, length);
}
