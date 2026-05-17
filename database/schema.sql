-- Hospital Management System
-- Database Schema
-- CSD209A | Ramaiah University of Applied Sciences

-- 1. USERS
CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK(role IN ('Admin', 'Doctor', 
                          'Receptionist', 'Nurse', 'Staff'))
);

-- 2. DEPARTMENTS
CREATE TABLE IF NOT EXISTS departments (
    dept_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    location    TEXT    NOT NULL
);

-- 3. DOCTORS
CREATE TABLE IF NOT EXISTS doctors (
    doctor_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    specialization  TEXT    NOT NULL,
    contact         TEXT    NOT NULL UNIQUE,
    dept_id         INTEGER NOT NULL,
    user_id         INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (dept_id)  REFERENCES departments(dept_id),
    FOREIGN KEY (user_id)  REFERENCES users(user_id)
);

-- 4. STAFF
CREATE TABLE IF NOT EXISTS staff (
    staff_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    role_title  TEXT    NOT NULL,
    contact     TEXT    NOT NULL UNIQUE,
    dept_id     INTEGER NOT NULL,
    user_id     INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (dept_id)  REFERENCES departments(dept_id),
    FOREIGN KEY (user_id)  REFERENCES users(user_id)
);

-- 5. PATIENTS
CREATE TABLE IF NOT EXISTS patients (
    patient_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    dob         TEXT    NOT NULL,
    gender      TEXT    NOT NULL CHECK(gender IN ('Male', 'Female', 'Other')),
    contact     TEXT    NOT NULL UNIQUE,
    address     TEXT    NOT NULL,
    blood_group TEXT    NOT NULL CHECK(blood_group IN (
                        'A+', 'A-', 'B+', 'B-', 
                        'AB+', 'AB-', 'O+', 'O-'))
);

-- 6. APPOINTMENTS
CREATE TABLE IF NOT EXISTS appointments (
    appt_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id  INTEGER NOT NULL,
    doctor_id   INTEGER NOT NULL,
    date        TEXT    NOT NULL,
    time        TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'Scheduled'
                        CHECK(status IN ('Scheduled', 'Completed', 'Cancelled')),
    UNIQUE (doctor_id, date, time),
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    FOREIGN KEY (doctor_id)  REFERENCES doctors(doctor_id)
);

-- 7. MEDICAL RECORDS
CREATE TABLE IF NOT EXISTS medical_records (
    record_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    appt_id     INTEGER NOT NULL UNIQUE,
    diagnosis   TEXT    NOT NULL,
    medications TEXT    NOT NULL,
    notes       TEXT,
    FOREIGN KEY (appt_id) REFERENCES appointments(appt_id)
);

-- 8. BILLING
CREATE TABLE IF NOT EXISTS billing (
    bill_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    appt_id     INTEGER NOT NULL UNIQUE,
    amount      REAL    NOT NULL CHECK(amount > 0),
    status      TEXT    NOT NULL DEFAULT 'Unpaid'
                        CHECK(status IN ('Paid', 'Unpaid')),
    date        TEXT    NOT NULL,
    FOREIGN KEY (appt_id) REFERENCES appointments(appt_id)
);