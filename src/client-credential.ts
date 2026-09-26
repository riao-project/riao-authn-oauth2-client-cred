/**
 * OAuth2 Client Credential Record
 * Stored in database to track client credentials and their lifecycle
 */
import { randomBytes } from 'crypto';

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
 * Generate a cryptographically secure random secret
 * @param length Length of secret to generate (default: 32)
 * @returns Random alphanumeric secret
 */
export function generateSecret(length: number = 32): string {
	const characters =
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const bytes = randomBytes(length);
	let result = '';

	for (let i = 0; i < length; i++) {
		result += characters[bytes[i] % characters.length];
	}

	return result;
}
