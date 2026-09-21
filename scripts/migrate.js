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
const result = await client.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
console.log(`Migración completa: ${result.rows.length} tablas disponibles.`);
client.close();
