import { createClient } from '@libsql/client';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHmac } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const COOKIE = 'dli_session';
const SESSION_SECONDS = 8 * 60 * 60;
const ROLES = ['secretaria', 'patricia', 'veronica', 'administrador'];
const PUBLIC_ROLES = ['secretaria', 'doctor', 'administrador'];
const DOCTORS = ['patricia', 'veronica'];
const LOCATIONS = ['aguilares', 'san-miguel'];

function db() {
  if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) throw new Error('Base de datos no configurada');
  return createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
}

function json(res, status, body, extra = {}) {
  res.status(status).setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  Object.entries(extra).forEach(([key, value]) => res.setHeader(key, value));
  res.end(JSON.stringify(body));
}

async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('JSON_INVALIDO'); }
}

function clean(value, max = 200) { return String(value ?? '').trim().slice(0, max); }
function onlyDigits(value) { return clean(value, 30).replace(/\D/g, ''); }
function todayAR() { return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Argentina/Buenos_Aires' }).format(new Date()); }
function validDate(value) { return /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T12:00:00Z`)); }
function validTime(value) { return /^(?:[01]\d|2[0-3]):(?:00|15|30|45)$/.test(value); }
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254; }
function validCredential(authType, credential) { return authType === 'pin' ? /^\d{4}$/.test(credential) : authType === 'password' && credential.length >= 12; }

async function passwordHash(password) {
  const salt = randomBytes(16).toString('base64url');
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt}$${Buffer.from(derived).toString('base64url')}`;
}

async function passwordVerify(password, encoded) {
  try {
    const [name, n, r, p, salt, stored] = encoded.split('$');
    if (name !== 'scrypt') return false;
    const derived = await scrypt(password, salt, 64, { N: Number(n), r: Number(r), p: Number(p) });
    const expected = Buffer.from(stored, 'base64url');
    return expected.length === derived.length && timingSafeEqual(expected, derived);
  } catch { return false; }
}

function sign(value) {
  if (!process.env.AUTH_SECRET) throw new Error('Autenticación no configurada');
  return createHmac('sha256', process.env.AUTH_SECRET).update(value).digest('base64url');
}

function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({ id: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => { const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))]; }));
}

async function session(req) {
  const token = readCookies(req)[COOKIE];
  if (!token) return null;
  try {
    const [payload, signature] = token.split('.');
    const expected = sign(payload);
    if (!signature || signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (parsed.exp < Date.now() / 1000) return null;
    const result = await db().execute({ sql: 'SELECT id, username, display_name, role, doctor_key, auth_type FROM users WHERE id = ? AND active = 1', args: [parsed.id] });
    return result.rows[0] || null;
  } catch { return null; }
}

function cookie(token, maxAge = SESSION_SECONDS) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function audit(client, userId, action, entityType, entityId = null, details = null) {
  await client.execute({ sql: 'INSERT INTO audit_log (user_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)', args: [userId, action, entityType, entityId, details ? JSON.stringify(details).slice(0, 2000) : null] });
}

function requireRole(user, allowed) {
  if (!user) { const error = new Error('AUTH'); error.status = 401; throw error; }
  if (!allowed.includes(user.role)) { const error = new Error('FORBIDDEN'); error.status = 403; throw error; }
}

function publicUser(user) {
  if (!user) return null;
  const role = DOCTORS.includes(String(user.role)) ? 'doctor' : String(user.role);
  return { id: user.id, username: user.username, name: user.display_name, role, doctor: user.doctor_key || (DOCTORS.includes(String(user.role)) ? user.role : null), authType: user.auth_type };
}

async function bootstrap(client, input) {
  const count = await client.execute('SELECT COUNT(*) AS total FROM users');
  if (Number(count.rows[0].total) > 0) return { status: 409, body: { error: 'La configuración inicial ya fue realizada.' } };
  if (!process.env.BOOTSTRAP_SECRET || clean(input.setupKey, 300) !== process.env.BOOTSTRAP_SECRET) return { status: 403, body: { error: 'Clave de configuración inicial incorrecta.' } };
  const username = clean(input.username, 50).toLowerCase();
  const password = String(input.password || '');
  if (!/^[a-z0-9._-]{4,50}$/.test(username) || password.length < 12) return { status: 400, body: { error: 'Usá un usuario válido y una contraseña de al menos 12 caracteres.' } };
  const hash = await passwordHash(password);
  const result = await client.execute({ sql: "INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, 'administrador', ?) RETURNING id, username, display_name, role", args: [username, clean(input.displayName, 100) || 'Administrador', hash] });
  await audit(client, result.rows[0].id, 'bootstrap', 'user', result.rows[0].id);
  return { status: 201, body: { ok: true } };
}

async function availableSlots(client, query) {
  const doctor = clean(query.doctor, 20), location = clean(query.location, 30), date = clean(query.date, 10);
  if (!DOCTORS.includes(doctor) || !LOCATIONS.includes(location) || !validDate(date) || date < todayAR()) return { status: 400, body: { error: 'Selección inválida.' } };
  const weekday = new Date(`${date}T12:00:00Z`).getUTCDay();
  const schedules = await client.execute({ sql: 'SELECT start_time, end_time FROM schedules WHERE doctor_key = ? AND location_key = ? AND weekday = ? AND active = 1', args: [doctor, location, weekday] });
  const blocks = await client.execute({ sql: 'SELECT start_time, end_time FROM schedule_blocks WHERE doctor_key = ? AND location_key = ? AND block_date = ?', args: [doctor, location, date] });
  const bookings = await client.execute({ sql: "SELECT appointment_time FROM appointments WHERE doctor_key = ? AND location_key = ? AND appointment_date = ? AND status IN ('confirmado','atendido')", args: [doctor, location, date] });
  const occupied = new Set(bookings.rows.map(row => String(row.appointment_time)));
  const isBlocked = time => blocks.rows.some(row => String(row.start_time) <= time && time < String(row.end_time));
  const slots = [];
  for (const schedule of schedules.rows) {
    let [h, m] = String(schedule.start_time).split(':').map(Number);
    const [eh, em] = String(schedule.end_time).split(':').map(Number);
    let cursor = h * 60 + m, end = eh * 60 + em;
    while (cursor + 15 <= end) {
      const time = `${String(Math.floor(cursor / 60)).padStart(2, '0')}:${String(cursor % 60).padStart(2, '0')}`;
      if (!occupied.has(time) && !isBlocked(time)) slots.push(time);
      cursor += 15;
    }
  }
  return { status: 200, body: { slots: [...new Set(slots)].sort() } };
}

async function createAppointment(client, input) {
  const data = {
    doctor: clean(input.doctor, 20), location: clean(input.location, 30), date: clean(input.date, 10), time: clean(input.time, 5),
    firstName: clean(input.firstName, 80), lastName: clean(input.lastName, 80), document: onlyDigits(input.document),
    birthDate: clean(input.birthDate, 10), phone: clean(input.phone, 40), guardianName: clean(input.guardianName, 160), notes: clean(input.notes, 300)
  };
  if (!DOCTORS.includes(data.doctor) || !LOCATIONS.includes(data.location) || !validDate(data.date) || data.date < todayAR() || !validTime(data.time)) return { status: 400, body: { error: 'El turno seleccionado no es válido.' } };
  if (!data.firstName || !data.lastName || data.document.length < 6 || !validDate(data.birthDate) || onlyDigits(data.phone).length < 8) return { status: 400, body: { error: 'Completá correctamente los datos obligatorios.' } };
  const availability = await availableSlots(client, { doctor: data.doctor, location: data.location, date: data.date });
  if (!availability.body.slots?.includes(data.time)) return { status: 409, body: { error: 'Ese horario ya no está disponible. Elegí otro.' } };
  const receipt = randomBytes(6).toString('hex').toUpperCase();
  try {
    const batch = await client.batch([
      { sql: `INSERT INTO patients (document_number, first_name, last_name, birth_date, phone, guardian_name)
              VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(document_number) DO UPDATE SET first_name=excluded.first_name, last_name=excluded.last_name, birth_date=excluded.birth_date, phone=excluded.phone, guardian_name=COALESCE(NULLIF(excluded.guardian_name,''), patients.guardian_name)`, args: [data.document, data.firstName, data.lastName, data.birthDate, data.phone, data.guardianName || null] },
      { sql: `INSERT INTO appointments (patient_id, doctor_key, location_key, appointment_date, appointment_time, status, public_notes, receipt_code)
              SELECT id, ?, ?, ?, ?, 'confirmado', ?, ? FROM patients WHERE document_number = ?`, args: [data.doctor, data.location, data.date, data.time, data.notes || null, receipt, data.document] }
    ], 'write');
    const id = Number(batch[1].lastInsertRowid);
    return { status: 201, body: { ok: true, appointment: { id, receipt, ...data, status: 'confirmado' } } };
  } catch (error) {
    if (/UNIQUE|constraint/i.test(String(error))) return { status: 409, body: { error: 'Ese horario acaba de ser reservado. Elegí otro.' } };
    throw error;
  }
}

async function login(client, input) {
  const username = clean(input.username, 50).toLowerCase();
  const result = await client.execute({ sql: 'SELECT * FROM users WHERE username = ? AND active = 1', args: [username] });
  const user = result.rows[0];
  if (user?.locked_until && new Date(`${String(user.locked_until).replace(' ', 'T')}Z`).getTime() > Date.now()) return { status: 429, body: { error: 'Acceso bloqueado temporalmente por varios intentos fallidos. Probá nuevamente en 15 minutos.' } };
  const credential = String(input.credential || input.password || '');
  if (!user || !(await passwordVerify(credential, String(user.password_hash)))) {
    if (user) await client.execute({ sql: "UPDATE users SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN failed_attempts+1>=5 THEN datetime('now','+15 minutes') ELSE locked_until END WHERE id=?", args: [user.id] });
    return { status: 401, body: { error: 'Usuario o contraseña/PIN incorrectos.' } };
  }
  await client.execute({ sql: 'UPDATE users SET last_login_at=CURRENT_TIMESTAMP, failed_attempts=0, locked_until=NULL WHERE id=?', args: [user.id] });
  await audit(client, user.id, 'login', 'session');
  return { status: 200, body: { ok: true, user: publicUser(user) }, headers: { 'Set-Cookie': cookie(makeSession(user)) } };
}

async function dashboard(client, user) {
  requireRole(user, ROLES);
  const appointments = await client.execute(`SELECT a.id, a.doctor_key, a.location_key, a.appointment_date, a.appointment_time, a.status, a.public_notes,
    p.id AS patient_id, p.first_name, p.last_name, p.document_number, p.birth_date, p.phone, p.guardian_name
    FROM appointments a JOIN patients p ON p.id=a.patient_id ORDER BY a.appointment_date DESC, a.appointment_time DESC LIMIT 300`);
  const schedules = await client.execute('SELECT * FROM schedules ORDER BY doctor_key, location_key, weekday, start_time');
  return { status: 200, body: { user: publicUser(user), appointments: appointments.rows, schedules: schedules.rows } };
}

async function patients(client, user, query) {
  requireRole(user, ['patricia', 'veronica', 'administrador']);
  const search = `%${clean(query.search, 80)}%`;
  const result = await client.execute({ sql: `SELECT id, document_number, first_name, last_name, birth_date, phone, guardian_name, allergies, alerts, background
    FROM patients WHERE first_name LIKE ? OR last_name LIKE ? OR document_number LIKE ? ORDER BY last_name, first_name LIMIT 100`, args: [search, search, search] });
  await audit(client, user.id, 'list', 'patient');
  return { status: 200, body: { patients: result.rows } };
}

async function clinicalHistory(client, user, patientId) {
  requireRole(user, ['patricia', 'veronica', 'administrador']);
  const patient = await client.execute({ sql: 'SELECT * FROM patients WHERE id = ?', args: [patientId] });
  if (!patient.rows[0]) return { status: 404, body: { error: 'Paciente no encontrado.' } };
  const entries = await client.execute({ sql: `SELECT e.*, u.display_name AS author_name FROM clinical_entries e JOIN users u ON u.id=e.author_user_id
    WHERE e.patient_id=? ORDER BY e.created_at DESC`, args: [patientId] });
  await audit(client, user.id, 'view', 'clinical_history', patientId);
  return { status: 200, body: { patient: patient.rows[0], entries: entries.rows } };
}

async function createClinicalEntry(client, user, input) {
  requireRole(user, ['patricia', 'veronica', 'administrador']);
  const patientId = Number(input.patientId), appointmentId = input.appointmentId ? Number(input.appointmentId) : null;
  const fields = ['reason', 'evaluation', 'diagnosis', 'indications', 'treatment', 'studies', 'evolution', 'nextControl'];
  const values = Object.fromEntries(fields.map(key => [key, clean(input[key], 5000)]));
  if (!patientId || !values.reason || !values.evaluation) return { status: 400, body: { error: 'El motivo y la evaluación son obligatorios.' } };
  const doctor = user.role === 'administrador' ? clean(input.doctor, 20) : String(user.doctor_key || user.role);
  if (!DOCTORS.includes(doctor)) return { status: 400, body: { error: 'Seleccioná la doctora responsable.' } };
  const result = await client.execute({ sql: `INSERT INTO clinical_entries (patient_id, appointment_id, doctor_key, author_user_id, location_key, reason, evaluation, diagnosis, indications, treatment, studies, evolution, next_control, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cerrada') RETURNING id`, args: [patientId, appointmentId, doctor, user.id, clean(input.location, 30) || null, values.reason, values.evaluation, values.diagnosis || null, values.indications || null, values.treatment || null, values.studies || null, values.evolution || null, values.nextControl || null] });
  if (appointmentId) await client.execute({ sql: "UPDATE appointments SET status='atendido', updated_at=CURRENT_TIMESTAMP WHERE id=?", args: [appointmentId] });
  await audit(client, user.id, 'create', 'clinical_entry', result.rows[0].id, { patientId, doctor });
  return { status: 201, body: { ok: true, id: result.rows[0].id } };
}

async function createCorrection(client, user, input) {
  requireRole(user, ['patricia', 'veronica', 'administrador']);
  const entryId = Number(input.entryId), reason = clean(input.reason, 1000), correction = clean(input.correction, 5000);
  if (!entryId || !reason || !correction) return { status: 400, body: { error: 'Indicá el motivo y la corrección.' } };
  const result = await client.execute({ sql: 'INSERT INTO clinical_corrections (entry_id, author_user_id, reason, correction) VALUES (?, ?, ?, ?) RETURNING id', args: [entryId, user.id, reason, correction] });
  await audit(client, user.id, 'correct', 'clinical_entry', entryId, { correctionId: result.rows[0].id });
  return { status: 201, body: { ok: true } };
}

async function updateAppointment(client, user, input) {
  requireRole(user, ROLES);
  const id = Number(input.id), status = clean(input.status, 20);
  if (!id || !['confirmado', 'atendido', 'cancelado', 'ausente'].includes(status)) return { status: 400, body: { error: 'Cambio inválido.' } };
  await client.execute({ sql: 'UPDATE appointments SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', args: [status, id] });
  await audit(client, user.id, 'update_status', 'appointment', id, { status });
  return { status: 200, body: { ok: true } };
}

async function saveSchedule(client, user, input) {
  requireRole(user, ['administrador']);
  const doctor = clean(input.doctor, 20), location = clean(input.location, 30), weekday = Number(input.weekday), start = clean(input.start, 5), end = clean(input.end, 5);
  if (!DOCTORS.includes(doctor) || !LOCATIONS.includes(location) || weekday < 0 || weekday > 6 || !validTime(start) || !validTime(end) || start >= end) return { status: 400, body: { error: 'Horario inválido.' } };
  const result = await client.execute({ sql: 'INSERT INTO schedules (doctor_key, location_key, weekday, start_time, end_time) VALUES (?, ?, ?, ?, ?) RETURNING id', args: [doctor, location, weekday, start, end] });
  await audit(client, user.id, 'create', 'schedule', result.rows[0].id);
  return { status: 201, body: { ok: true } };
}

async function createUser(client, user, input) {
  requireRole(user, ['administrador']);
  const username = clean(input.username, 50).toLowerCase(), role = clean(input.role, 20), doctorKey = role === 'doctor' ? clean(input.doctor, 20) : null, authType = clean(input.authType, 20) || 'password', credential = String(input.credential || input.password || ''), displayName = clean(input.displayName, 100);
  if (!PUBLIC_ROLES.includes(role) || (role === 'doctor' && !DOCTORS.includes(doctorKey)) || !['password','pin'].includes(authType) || !/^[a-z0-9._-]{4,50}$/.test(username) || !validCredential(authType, credential) || !displayName) return { status: 400, body: { error: role === 'doctor' && !DOCTORS.includes(doctorKey) ? 'Seleccioná la doctora asociada a la cuenta.' : authType === 'pin' ? 'El PIN debe tener exactamente 4 números.' : 'La contraseña debe tener al menos 12 caracteres.' } };
  const storedRole = role === 'doctor' ? doctorKey : role;
  try {
    const result = await client.execute({ sql: 'INSERT INTO users (username, display_name, role, doctor_key, password_hash, auth_type) VALUES (?, ?, ?, ?, ?, ?) RETURNING id', args: [username, displayName, storedRole, doctorKey, await passwordHash(credential), authType] });
    await audit(client, user.id, 'create', 'user', result.rows[0].id, { role, doctor: doctorKey, authType });
    return { status: 201, body: { ok: true } };
  } catch (error) {
    if (/UNIQUE/i.test(String(error))) return { status: 409, body: { error: 'Ese nombre de usuario ya existe.' } };
    throw error;
  }
}

async function changePassword(client, user, input) {
  requireRole(user, ROLES);
  const current = String(input.currentCredential || input.currentPassword || ''), next = String(input.newCredential || input.newPassword || ''), authType = clean(input.authType, 20) || 'password';
  if (!['password','pin'].includes(authType) || !validCredential(authType, next)) return { status: 400, body: { error: authType === 'pin' ? 'El PIN debe tener exactamente 4 números.' : 'La nueva contraseña debe tener al menos 12 caracteres.' } };
  const result = await client.execute({ sql: 'SELECT password_hash FROM users WHERE id=?', args: [user.id] });
  if (!result.rows[0] || !(await passwordVerify(current, String(result.rows[0].password_hash)))) return { status: 401, body: { error: 'La contraseña o el PIN actual no es correcto.' } };
  await client.execute({ sql: 'UPDATE users SET password_hash=?, auth_type=?, failed_attempts=0, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?', args: [await passwordHash(next), authType, user.id] });
  await audit(client, user.id, 'change_credential', 'user', user.id, { authType });
  return { status: 200, body: { ok: true } };
}

async function sendReceipt(client, input) {
  const email = clean(input.email, 254);
  if (!validEmail(email)) return { status: 400, body: { error: 'Ingresá un correo válido.' } };
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) return { status: 503, body: { error: 'El envío por correo todavía no está configurado. Podés imprimir o guardar el comprobante.' } };
  const id = Number(input.id), receipt = clean(input.receipt, 30);
  const found = await client.execute({ sql: `SELECT a.id, a.receipt_code, a.doctor_key, a.location_key, a.appointment_date, a.appointment_time, p.first_name, p.last_name
    FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.id=? AND a.receipt_code=?`, args: [id, receipt] });
  if (!found.rows[0]) return { status: 404, body: { error: 'No se encontró el comprobante solicitado.' } };
  const appointment = found.rows[0];
  const doctorNames = { patricia: 'Dra. Patricia Noelia Leiva Ibañez', veronica: 'Dra. Maria Veronica Leiva Ibañez' };
  const locationNames = { aguilares: 'Aguilares', 'san-miguel': 'San Miguel de Tucumán' };
  const safe = value => clean(value, 300).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({
    from: process.env.EMAIL_FROM, to: [email], subject: 'Comprobante de turno confirmado · Dras. Leiva Ibañez',
    html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#18372f"><h1>Turno confirmado</h1><p><strong>Paciente:</strong> ${safe(appointment.first_name)} ${safe(appointment.last_name)}</p><p><strong>Profesional:</strong> ${safe(doctorNames[appointment.doctor_key])}</p><p><strong>Localidad:</strong> ${safe(locationNames[appointment.location_key])}</p><p><strong>Fecha y hora:</strong> ${safe(appointment.appointment_date)} · ${safe(appointment.appointment_time)}</p><p><strong>Comprobante:</strong> ${safe(appointment.receipt_code)}</p><hr><p>Si surge algún inconveniente, Secretaría se comunicará al teléfono informado.</p></div>`
  }) });
  if (!response.ok) return { status: 502, body: { error: 'No se pudo enviar el correo. El turno continúa confirmado.' } };
  return { status: 200, body: { ok: true } };
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, 'https://local');
    const action = url.searchParams.get('action') || '';
    const client = db();
    const input = req.method === 'GET' ? Object.fromEntries(url.searchParams) : await body(req);
    const user = await session(req);
    let result;
    if (req.method === 'GET' && action === 'health') result = { status: 200, body: { ok: true } };
    else if (req.method === 'GET' && action === 'slots') result = await availableSlots(client, input);
    else if (req.method === 'POST' && action === 'appointment') result = await createAppointment(client, input);
    else if (req.method === 'POST' && action === 'receipt-email') result = await sendReceipt(client, input);
    else if (req.method === 'POST' && action === 'bootstrap') result = await bootstrap(client, input);
    else if (req.method === 'POST' && action === 'login') result = await login(client, input);
    else if (req.method === 'POST' && action === 'logout') result = { status: 200, body: { ok: true }, headers: { 'Set-Cookie': cookie('', 0) } };
    else if (req.method === 'GET' && action === 'session') result = { status: 200, body: { user: publicUser(user) } };
    else if (req.method === 'GET' && action === 'dashboard') result = await dashboard(client, user);
    else if (req.method === 'GET' && action === 'patients') result = await patients(client, user, input);
    else if (req.method === 'GET' && action === 'history') result = await clinicalHistory(client, user, Number(input.patientId));
    else if (req.method === 'POST' && action === 'clinical-entry') result = await createClinicalEntry(client, user, input);
    else if (req.method === 'POST' && action === 'clinical-correction') result = await createCorrection(client, user, input);
    else if (req.method === 'POST' && action === 'appointment-status') result = await updateAppointment(client, user, input);
    else if (req.method === 'POST' && action === 'schedule') result = await saveSchedule(client, user, input);
    else if (req.method === 'POST' && action === 'user') result = await createUser(client, user, input);
    else if (req.method === 'POST' && action === 'change-password') result = await changePassword(client, user, input);
    else result = { status: 404, body: { error: 'Ruta no encontrada.' } };
    json(res, result.status, result.body, result.headers);
  } catch (error) {
    const status = error.status || (error.message === 'JSON_INVALIDO' ? 400 : 500);
    console.error('API error', error.message);
    json(res, status, { error: status === 500 ? 'No se pudo completar la operación.' : error.message });
  }
}

export { passwordHash, passwordVerify, publicUser, validCredential, validDate, validTime };
