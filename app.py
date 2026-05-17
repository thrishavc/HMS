import os
import sqlite3
from datetime import date
from functools import wraps

import bcrypt
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "hms.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "hms-dev-secret-key-change-in-production")

ROLES = ["Admin", "Doctor", "Receptionist", "Nurse", "Staff"]
GENDERS = ["Male", "Female", "Other"]
BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
ADMIN_ONLY = ("Admin",)
MEDICAL_ROLES = ("Admin", "Doctor")
PATIENT_ROLES = ("Admin", "Receptionist", "Nurse", "Staff")
APPOINTMENT_ROLES = ("Admin", "Doctor", "Receptionist", "Nurse", "Staff")
BILLING_ROLES = ("Admin", "Receptionist", "Nurse", "Staff")


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.context_processor
def inject_globals():
    return {
        "current_username": session.get("username"),
        "current_role": session.get("role"),
    }


def verify_password(plain_password, password_hash):
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


def hash_password(plain_password):
    return bcrypt.hashpw(
        plain_password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


@app.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT user_id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    stats = {
        "patients": db.execute("SELECT COUNT(*) AS c FROM patients").fetchone()["c"],
        "doctors": db.execute("SELECT COUNT(*) AS c FROM doctors").fetchone()["c"],
        "staff": db.execute("SELECT COUNT(*) AS c FROM staff").fetchone()["c"],
        "scheduled": db.execute(
            "SELECT COUNT(*) AS c FROM appointments WHERE status = 'Scheduled'"
        ).fetchone()["c"],
        "pending_bills": db.execute(
            "SELECT COUNT(*) AS c FROM billing WHERE status = 'Unpaid'"
        ).fetchone()["c"],
        "departments": db.execute(
            "SELECT COUNT(*) AS c FROM departments"
        ).fetchone()["c"],
    }
    return render_template("dashboard.html", stats=stats)


@app.route("/users", methods=["GET", "POST"])
@login_required
@roles_required(*ADMIN_ONLY)
def users():
    db = get_db()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if not username or not password or role not in ROLES:
            flash("All fields are required.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, hash_password(password), role),
                )
                db.commit()
                flash("User created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Username already exists.", "error")

        return redirect(url_for("users"))

    user_rows = db.execute(
        "SELECT user_id, username, role FROM users ORDER BY user_id"
    ).fetchall()
    return render_template("users.html", users=user_rows, roles=ROLES)


@app.route("/departments", methods=["GET", "POST"])
@login_required
@roles_required(*ADMIN_ONLY)
def departments():
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        location = request.form.get("location", "").strip()

        if not name or not location:
            flash("Department name and location are required.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO departments (name, location) VALUES (?, ?)",
                    (name, location),
                )
                db.commit()
                flash("Department added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Department name already exists.", "error")

        return redirect(url_for("departments"))

    dept_rows = db.execute(
        "SELECT dept_id, name, location FROM departments ORDER BY dept_id"
    ).fetchall()
    return render_template("departments.html", departments=dept_rows)


@app.route("/doctors", methods=["GET", "POST"])
@login_required
@roles_required(*ADMIN_ONLY)
def doctors():
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        specialization = request.form.get("specialization", "").strip()
        contact = request.form.get("contact", "").strip()
        dept_id = request.form.get("dept_id")
        user_id = request.form.get("user_id")

        if not all([name, specialization, contact, dept_id, user_id]):
            flash("All fields are required.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO doctors (name, specialization, contact, dept_id, user_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, specialization, contact, dept_id, user_id),
                )
                db.commit()
                flash("Doctor added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Contact or user account already assigned.", "error")

        return redirect(url_for("doctors"))

    doctor_rows = db.execute(
        """SELECT d.doctor_id, d.name, d.specialization, d.contact,
                  dep.name AS department
           FROM doctors d
           JOIN departments dep ON d.dept_id = dep.dept_id
           ORDER BY d.doctor_id"""
    ).fetchall()

    departments_list = db.execute(
        "SELECT dept_id, name FROM departments ORDER BY name"
    ).fetchall()

    available_users = db.execute(
        """SELECT user_id, username FROM users
           WHERE role = 'Doctor'
             AND user_id NOT IN (SELECT user_id FROM doctors)
           ORDER BY username"""
    ).fetchall()

    return render_template(
        "doctors.html",
        doctors=doctor_rows,
        departments=departments_list,
        available_users=available_users,
    )


@app.route("/staff", methods=["GET", "POST"])
@login_required
@roles_required(*ADMIN_ONLY)
def staff():
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        role_title = request.form.get("role_title", "").strip()
        contact = request.form.get("contact", "").strip()
        dept_id = request.form.get("dept_id")
        user_id = request.form.get("user_id")

        if not all([name, role_title, contact, dept_id, user_id]):
            flash("All fields are required.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO staff (name, role_title, contact, dept_id, user_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, role_title, contact, dept_id, user_id),
                )
                db.commit()
                flash("Staff member added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Contact or user account already assigned.", "error")

        return redirect(url_for("staff"))

    staff_rows = db.execute(
        """SELECT s.staff_id, s.name, s.role_title, s.contact,
                  dep.name AS department
           FROM staff s
           JOIN departments dep ON s.dept_id = dep.dept_id
           ORDER BY s.staff_id"""
    ).fetchall()

    departments_list = db.execute(
        "SELECT dept_id, name FROM departments ORDER BY name"
    ).fetchall()

    available_users = db.execute(
        """SELECT user_id, username FROM users
           WHERE role NOT IN ('Admin', 'Doctor')
             AND user_id NOT IN (SELECT user_id FROM staff)
           ORDER BY username"""
    ).fetchall()

    return render_template(
        "staff.html",
        staff_members=staff_rows,
        departments=departments_list,
        available_users=available_users,
    )


@app.route("/patients", methods=["GET", "POST"])
@login_required
@roles_required(*PATIENT_ROLES)
def patients():
    db = get_db()
    search = request.args.get("q", "").strip()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        dob = request.form.get("dob", "").strip()
        gender = request.form.get("gender", "")
        contact = request.form.get("contact", "").strip()
        address = request.form.get("address", "").strip()
        blood_group = request.form.get("blood_group", "")

        if not all([name, dob, gender, contact, address, blood_group]):
            flash("All fields are required.", "error")
        elif gender not in GENDERS or blood_group not in BLOOD_GROUPS:
            flash("Invalid gender or blood group.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO patients (name, dob, gender, contact, address, blood_group)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (name, dob, gender, contact, address, blood_group),
                )
                db.commit()
                flash("Patient added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Contact number already exists.", "error")

        return redirect(url_for("patients", q=search))

    if search:
        patient_rows = db.execute(
            """SELECT patient_id, name, gender, contact, blood_group
               FROM patients
               WHERE name LIKE ? OR contact LIKE ? OR blood_group LIKE ?
               ORDER BY patient_id""",
            (f"%{search}%", f"%{search}%", f"%{search}%"),
        ).fetchall()
    else:
        patient_rows = db.execute(
            """SELECT patient_id, name, gender, contact, blood_group
               FROM patients ORDER BY patient_id"""
        ).fetchall()

    return render_template(
        "patients.html",
        patients=patient_rows,
        genders=GENDERS,
        blood_groups=BLOOD_GROUPS,
        search=search,
    )


@app.route("/appointments", methods=["GET", "POST"])
@login_required
@roles_required(*APPOINTMENT_ROLES)
def appointments():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            patient_id = request.form.get("patient_id")
            doctor_id = request.form.get("doctor_id")
            appt_date = request.form.get("date", "").strip()
            appt_time = request.form.get("time", "").strip()

            if not all([patient_id, doctor_id, appt_date, appt_time]):
                flash("All fields are required.", "error")
            else:
                try:
                    db.execute(
                        """INSERT INTO appointments (patient_id, doctor_id, date, time, status)
                           VALUES (?, ?, ?, ?, 'Scheduled')""",
                        (patient_id, doctor_id, appt_date, appt_time),
                    )
                    db.commit()
                    flash("Appointment scheduled successfully.", "success")
                except sqlite3.IntegrityError:
                    flash(
                        "This time slot is already booked for the selected doctor.",
                        "error",
                    )

        elif action == "complete":
            appt_id = request.form.get("appt_id")
            db.execute(
                "UPDATE appointments SET status = 'Completed' WHERE appt_id = ? AND status = 'Scheduled'",
                (appt_id,),
            )
            db.commit()
            flash("Appointment marked as completed.", "success")

        elif action == "cancel":
            appt_id = request.form.get("appt_id")
            db.execute(
                "UPDATE appointments SET status = 'Cancelled' WHERE appt_id = ? AND status = 'Scheduled'",
                (appt_id,),
            )
            db.commit()
            flash("Appointment cancelled.", "success")

        return redirect(url_for("appointments"))

    appt_rows = db.execute(
        """SELECT a.appt_id, p.name AS patient_name, d.name AS doctor_name,
                  a.date, a.time, a.status
           FROM appointments a
           JOIN patients p ON a.patient_id = p.patient_id
           JOIN doctors d ON a.doctor_id = d.doctor_id
           ORDER BY a.date DESC, a.time DESC"""
    ).fetchall()

    patient_list = db.execute(
        "SELECT patient_id, name FROM patients ORDER BY name"
    ).fetchall()

    doctor_list = db.execute(
        "SELECT doctor_id, name FROM doctors ORDER BY name"
    ).fetchall()

    return render_template(
        "appointments.html",
        appointments=appt_rows,
        patients=patient_list,
        doctors=doctor_list,
    )


@app.route("/medical-records", methods=["GET", "POST"])
@login_required
@roles_required(*MEDICAL_ROLES)
def medical_records():
    db = get_db()

    if request.method == "POST":
        appt_id = request.form.get("appt_id")
        diagnosis = request.form.get("diagnosis", "").strip()
        medications = request.form.get("medications", "").strip()
        notes = request.form.get("notes", "").strip()

        if not appt_id or not diagnosis or not medications:
            flash("Appointment, diagnosis, and medications are required.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO medical_records (appt_id, diagnosis, medications, notes)
                       VALUES (?, ?, ?, ?)""",
                    (appt_id, diagnosis, medications, notes or None),
                )
                db.commit()
                flash("Medical record created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("A record already exists for this appointment.", "error")

        return redirect(url_for("medical_records"))

    record_rows = db.execute(
        """SELECT mr.record_id, p.name AS patient_name, d.name AS doctor_name,
                  a.date, mr.diagnosis
           FROM medical_records mr
           JOIN appointments a ON mr.appt_id = a.appt_id
           JOIN patients p ON a.patient_id = p.patient_id
           JOIN doctors d ON a.doctor_id = d.doctor_id
           ORDER BY mr.record_id DESC"""
    ).fetchall()

    available_appts = db.execute(
        """SELECT a.appt_id, p.name AS patient_name, d.name AS doctor_name, a.date
           FROM appointments a
           JOIN patients p ON a.patient_id = p.patient_id
           JOIN doctors d ON a.doctor_id = d.doctor_id
           LEFT JOIN medical_records mr ON a.appt_id = mr.appt_id
           WHERE a.status = 'Completed' AND mr.record_id IS NULL
           ORDER BY a.date DESC"""
    ).fetchall()

    return render_template(
        "medical_records.html",
        records=record_rows,
        available_appts=available_appts,
    )


@app.route("/billing", methods=["GET", "POST"])
@login_required
@roles_required(*BILLING_ROLES)
def billing():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            appt_id = request.form.get("appt_id")
            amount = request.form.get("amount", "").strip()

            try:
                amount_val = float(amount)
                if amount_val <= 0:
                    raise ValueError
            except ValueError:
                flash("Amount must be a number greater than zero.", "error")
                return redirect(url_for("billing"))

            try:
                db.execute(
                    """INSERT INTO billing (appt_id, amount, status, date)
                       VALUES (?, ?, 'Unpaid', ?)""",
                    (appt_id, amount_val, date.today().isoformat()),
                )
                db.commit()
                flash("Bill created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("A bill already exists for this appointment.", "error")

        elif action == "pay":
            bill_id = request.form.get("bill_id")
            db.execute(
                "UPDATE billing SET status = 'Paid' WHERE bill_id = ? AND status = 'Unpaid'",
                (bill_id,),
            )
            db.commit()
            flash("Bill marked as paid.", "success")

        return redirect(url_for("billing"))

    bill_rows = db.execute(
        """SELECT b.bill_id, p.name AS patient_name, d.name AS doctor_name,
                  a.date, b.amount, b.status
           FROM billing b
           JOIN appointments a ON b.appt_id = a.appt_id
           JOIN patients p ON a.patient_id = p.patient_id
           JOIN doctors d ON a.doctor_id = d.doctor_id
           ORDER BY b.bill_id DESC"""
    ).fetchall()

    available_appts = db.execute(
        """SELECT a.appt_id, p.name AS patient_name, d.name AS doctor_name, a.date
           FROM appointments a
           JOIN patients p ON a.patient_id = p.patient_id
           JOIN doctors d ON a.doctor_id = d.doctor_id
           LEFT JOIN billing b ON a.appt_id = b.appt_id
           WHERE a.status = 'Completed' AND b.bill_id IS NULL
           ORDER BY a.date DESC"""
    ).fetchall()

    return render_template(
        "billing.html",
        bills=bill_rows,
        available_appts=available_appts,
    )


if __name__ == "__main__":
    app.run(debug=True)
