/**
 * OAuth2 Client Credential Record
 * Stored in database to track client credentials and their lifecycle
 */
export interface ClientCredential {
	id: string;
	principal_id: string;
	client_id: string;
	client_secret_hash: string;
	description?: string | null;
	create_timestamp: Date;
	deactivate_timestamp?: Date | null;
}
