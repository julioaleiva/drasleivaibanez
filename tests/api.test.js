import test from 'node:test';
import assert from 'node:assert/strict';
import { passwordHash, passwordVerify, validDate, validTime } from '../api/index.js';

test('las contraseñas se almacenan con sal y no como texto', async () => {
  const first = await passwordHash('Una clave segura 2026');
  const second = await passwordHash('Una clave segura 2026');
  assert.notEqual(first, second);
  assert.equal(first.includes('Una clave segura 2026'), false);
  assert.equal(await passwordVerify('Una clave segura 2026', first), true);
  assert.equal(await passwordVerify('otra clave', first), false);
});

test('solo se aceptan fechas y turnos de 15 minutos válidos', () => {
  assert.equal(validDate('2026-10-15'), true);
  assert.equal(validDate('15/10/2026'), false);
  assert.equal(validTime('09:15'), true);
  assert.equal(validTime('09:10'), false);
  assert.equal(validTime('24:00'), false);
});
