import { Migration, MigrationPackage } from '@riao/dbal';
import {
	CreateClientCredentialsTable,
} from './migrations/001-create-client-credentials-table';

/**
 * OAuth2 Client Credentials Authentication Migrations
 * Provides database schema for storing client credentials
 */
export class OAuth2ClientCredentialsMigrations extends MigrationPackage {
	override package = '@riao/authn-oauth2-client-cred';
	override name = '@riao/authn-oauth2-client-cred';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			'create-client-credentials-table': CreateClientCredentialsTable,
		};
	}
}
