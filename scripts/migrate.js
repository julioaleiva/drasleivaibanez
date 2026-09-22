import { createClient } from '@libsql/client';
import { readFile } from 'node:fs/promises';

const url = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;
if (!url || !authToken) throw new Error('Faltan TURSO_DATABASE_URL o TURSO_AUTH_TOKEN.');

const sql = await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8');
const statements = sql
  .split(';')
  .map(statement => statement.trim())
  .filter(Boolean)
  .filter(statement => !statement.startsWith('PRAGMA'));

const client = createClient({ url, authToken });
for (const statement of statements) await client.execute(statement);
const userColumns = new Set((await client.execute('PRAGMA table_info(users)')).rows.map(row => String(row.name)));
if (!userColumns.has('auth_type')) await client.execute("ALTER TABLE users ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'password'");
if (!userColumns.has('failed_attempts')) await client.execute('ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0');
if (!userColumns.has('locked_until')) await client.execute('ALTER TABLE users ADD COLUMN locked_until TEXT');
const result = await client.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
console.log(`Migración completa: ${result.rows.length} tablas disponibles.`);
client.close();
