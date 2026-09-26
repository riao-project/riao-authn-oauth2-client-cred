import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { ColumnType, Migration } from '@riao/dbal';

/**
 * Creates the oauth2_client_credentials table
 * Stores client credentials for OAuth2 authentication
 */
export class CreateClientCredentialsTable extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'oauth2_client_credentials',
			columns: [
				UUIDKeyColumn,
				{
					name: 'principal_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_principals',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				{
					name: 'client_id',
					type: ColumnType.VARCHAR,
					length: 255,
					required: true,
					isUnique: true,
				},
				{
					name: 'client_secret_hash',
					type: ColumnType.VARCHAR,
					length: 255,
					required: true,
				},
				{
					name: 'description',
					type: ColumnType.VARCHAR,
					length: 500,
					required: false,
				},
				CreateTimestampColumn,
				{
					name: 'deactivate_timestamp',
					type: ColumnType.TIMESTAMP,
					required: false,
				},
				{
					name: 'last_exchange_timestamp',
					type: ColumnType.TIMESTAMP,
					required: false,
				},
				{
					name: 'failed_exchange_count',
					type: ColumnType.INT,
					required: true,
					default: 0,
				},
			],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({
			tables: 'oauth2_client_credentials',
		});
	}
}
