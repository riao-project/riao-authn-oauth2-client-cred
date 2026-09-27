import { Migration, MigrationPackage } from '@riao/dbal';
import {
	CreateClientCredentialsTable,
} from './migrations/001-create-client-credentials-table';

/**
 * OAuth2 Client Credentials Authentication Migrations
 * Provides database schema for storing client credentials with:
 * - Principal foreign key with cascade delete
 * - Globally unique client_id constraint
 * - Bcrypt-hashed client secrets
 * - Usage tracking (last exchange timestamp,
 *   failed attempt counter)
 * - Credential lifecycle management
 *   (create, deactivate timestamps)
 */
type OAuth2MigrationMap = Record<string, typeof Migration<unknown>>;

export class OAuth2ClientCredentialsMigrations extends MigrationPackage {
	override package = '@riao/' + 'authn-oauth2-client-cred';
	override name = '@riao/' + 'authn-oauth2-client-cred';

	override async getMigrations(): Promise<OAuth2MigrationMap> {
		return {
			'create-client-credentials-table': CreateClientCredentialsTable,
		};
	}
}
