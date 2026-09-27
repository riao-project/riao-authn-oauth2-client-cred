import { DatabasePostgres18 } from '@riao/postgres';
import { DatabaseConnectionOptions } from '@riao/dbal';

/**
 * Example database for OAuth2 authentication
 * Connects to PostgreSQL with example configuration
 *
 * Environment variables used:
 * - DB_HOST: PostgreSQL host (default: localhost)
 * - DB_PORT: PostgreSQL port (default: 5432)
 * - DB_USER: PostgreSQL username (default: postgres)
 * - DB_PASSWORD: PostgreSQL password
 */
export default class ExampleDatabase extends DatabasePostgres18 {
	override name = 'example';

	public override async init(options?: {
		connectionOptions?: DatabaseConnectionOptions;
		useSchemaCache?: boolean;
	}): Promise<void> {
		// First, ensure the database exists by connecting to the default
		// 'postgres' database.
		const adminDb = new (
			class extends DatabasePostgres18 {
				override name = 'postgres';

				public override configureFromEnv(): void {
					// Copy env configuration from this instance.
					this.env = {
						NODE_ENV: process.env['NODE_ENV'] || 'development',
						host:
							options?.connectionOptions?.host ||
							process.env['DB_HOST'] ||
							'localhost',
						port:
							options?.connectionOptions?.port ||
							(process.env['DB_PORT']
								? parseInt(process.env['DB_PORT'], 10)
								: 5432),
						username:
							options?.connectionOptions?.username ||
							process.env['DB_USER'] ||
							'postgres',
						password:
							options?.connectionOptions?.password ||
							process.env['DB_PASSWORD'] ||
							'',
						database: this.name,
					};
				}
			}
		)();

		try {
			await adminDb.init(options);
			// Create the example database
			try {
				await adminDb.ddl.createDatabase({
					name: `"${this.name}"`,
				});
			}
			catch {
				// Database might already exist, ignore error
			}
			await adminDb.disconnect();
		}
		catch (error) {
			// Log but don't fail if database creation fails.
			process.stdout.write(`Note: ${(error as Error).message}\n`);
		}

		// Now connect to the example database
		await super.init(options);
	}
}

export const exampledb = new ExampleDatabase();
