PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('secretaria','patricia','veronica','administrador')),
  doctor_key TEXT CHECK(doctor_key IS NULL OR doctor_key IN ('patricia','veronica')),
  password_hash TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'password' CHECK(auth_type IN ('password','pin')),
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_number TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  birth_date TEXT NOT NULL,
  phone TEXT NOT NULL,
  guardian_name TEXT,
  allergies TEXT,
  alerts TEXT,
  background TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  doctor_key TEXT NOT NULL CHECK(doctor_key IN ('patricia','veronica')),
  location_key TEXT NOT NULL CHECK(location_key IN ('aguilares','san-miguel')),
  weekday INTEGER NOT NULL CHECK(weekday BETWEEN 0 AND 6),
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(start_time < end_time)
);

CREATE TABLE IF NOT EXISTS schedule_blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  doctor_key TEXT NOT NULL CHECK(doctor_key IN ('patricia','veronica')),
  location_key TEXT NOT NULL CHECK(location_key IN ('aguilares','san-miguel')),
  block_date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  reason TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  doctor_key TEXT NOT NULL CHECK(doctor_key IN ('patricia','veronica')),
  location_key TEXT NOT NULL CHECK(location_key IN ('aguilares','san-miguel')),
  appointment_date TEXT NOT NULL,
  appointment_time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'confirmado' CHECK(status IN ('confirmado','atendido','cancelado','ausente')),
  public_notes TEXT,
  receipt_code TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_appointment_per_slot
ON appointments(doctor_key, location_key, appointment_date, appointment_time)
WHERE status IN ('confirmado','atendido');

CREATE TABLE IF NOT EXISTS clinical_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  appointment_id INTEGER REFERENCES appointments(id),
  doctor_key TEXT NOT NULL CHECK(doctor_key IN ('patricia','veronica')),
  author_user_id INTEGER NOT NULL REFERENCES users(id),
  location_key TEXT CHECK(location_key IS NULL OR location_key IN ('aguilares','san-miguel')),
  reason TEXT NOT NULL,
  evaluation TEXT NOT NULL,
  diagnosis TEXT,
  indications TEXT,
  treatment TEXT,
  studies TEXT,
  evolution TEXT,
  next_control TEXT,
  status TEXT NOT NULL DEFAULT 'cerrada' CHECK(status IN ('borrador','cerrada')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clinical_corrections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL REFERENCES clinical_entries(id),
  author_user_id INTEGER NOT NULL REFERENCES users(id),
  reason TEXT NOT NULL,
  correction TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS appointments_by_date ON appointments(appointment_date, doctor_key, location_key);
CREATE INDEX IF NOT EXISTS clinical_entries_by_patient ON clinical_entries(patient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_by_entity ON audit_log(entity_type, entity_id, created_at DESC);
