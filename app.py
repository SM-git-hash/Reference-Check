import os
import secrets
import sqlite3
from contextlib import closing
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)

# Development fallback only. Set SECRET_KEY in the environment for production.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    str(Path(__file__).with_name("references.db")),
)

RATING_OPTIONS = {"Excellent", "Good", "Satisfactory", "Poor"}
REHIRE_OPTIONS = {"Yes", "No", "With reservations"}


def get_connection():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf_token():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(400)
    session.pop("csrf_token", None)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.path in ("/dashboard", "/database-view", "/create-request"):
        response.headers["Cache-Control"] = "no-store"

    return response


def init_database():
    with closing(get_connection()) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS reference_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_name TEXT NOT NULL,
                    referee_name TEXT NOT NULL,
                    referee_email TEXT NOT NULL,
                    organisation TEXT,
                    job_title TEXT,
                    token TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    submitted_at TIMESTAMP
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS references_table (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    candidate_name TEXT NOT NULL,
                    referee_name TEXT NOT NULL,
                    referee_email TEXT NOT NULL,
                    organisation TEXT,
                    job_title TEXT,
                    relationship TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    rehire TEXT NOT NULL,
                    clinical_competence TEXT NOT NULL,
                    communication_skills TEXT NOT NULL,
                    professional_conduct TEXT NOT NULL,
                    reference_text TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    token TEXT,
                    status TEXT DEFAULT 'completed',
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (request_id) REFERENCES reference_requests (id)
                )
            """)


def get_reference_form_data():
    fields = [
        "candidate_name",
        "referee_name",
        "referee_email",
        "organisation",
        "job_title",
        "relationship",
        "start_date",
        "end_date",
        "rehire",
        "clinical_competence",
        "communication_skills",
        "professional_conduct",
        "reference_text",
        "signature",
    ]
    return {field: request.form.get(field, "").strip() for field in fields}


def validate_reference(data):
    errors = []

    for field, value in data.items():
        if not value:
            errors.append(f"{field.replace('_', ' ').title()} is required.")

    if data["rehire"] and data["rehire"] not in REHIRE_OPTIONS:
        errors.append("Rehire must be a valid option.")

    for field in (
        "clinical_competence",
        "communication_skills",
        "professional_conduct",
    ):
        if data[field] and data[field] not in RATING_OPTIONS:
            errors.append(f"{field.replace('_', ' ').title()} must be a valid rating.")

    if data["start_date"] and data["end_date"] and data["start_date"] > data["end_date"]:
        errors.append("Employment start date cannot be after employment end date.")

    if len(data["reference_text"]) > 5000:
        errors.append("Reference comments must be 5,000 characters or fewer.")

    return errors


@app.route("/")
def home():
    return render_template(
        "index.html",
        csrf_token=generate_csrf_token(),
        form_data={},
        errors=[],
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    errors = []

    if request.method == "POST":
        validate_csrf_token()

        password = request.form.get("password", "")
        expected_password = os.environ.get("ADMIN_PASSWORD", "changeme")

        if secrets.compare_digest(password, expected_password):
            session["logged_in"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))

        errors.append("Invalid password.")

    return render_template(
        "login.html",
        csrf_token=generate_csrf_token(),
        errors=errors,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/create-request", methods=["GET", "POST"])
@login_required
def create_request():
    errors = []
    form_data = {
        "candidate_name": "",
        "referee_name": "",
        "referee_email": "",
        "organisation": "",
        "job_title": "",
    }

    if request.method == "POST":
        validate_csrf_token()

        form_data = {
            "candidate_name": request.form.get("candidate_name", "").strip(),
            "referee_name": request.form.get("referee_name", "").strip(),
            "referee_email": request.form.get("referee_email", "").strip(),
            "organisation": request.form.get("organisation", "").strip(),
            "job_title": request.form.get("job_title", "").strip(),
        }

        required_fields = [
            "candidate_name",
            "referee_name",
            "referee_email",
            "organisation",
            "job_title",
        ]

        for field in required_fields:
            if not form_data[field]:
                errors.append(f"{field.replace('_', ' ').title()} is required.")

        if not errors:
            token = secrets.token_urlsafe(32)

            with closing(get_connection()) as connection:
                with connection:
                    connection.execute("""
                        INSERT INTO reference_requests (
                            candidate_name,
                            referee_name,
                            referee_email,
                            organisation,
                            job_title,
                            token,
                            status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        form_data["candidate_name"],
                        form_data["referee_name"],
                        form_data["referee_email"],
                        form_data["organisation"],
                        form_data["job_title"],
                        token,
                        "pending",
                    ))

            secure_link = url_for("reference_by_token", token=token, _external=True)

            return render_template(
                "request_created.html",
                secure_link=secure_link,
            )

    return render_template(
        "create_request.html",
        csrf_token=generate_csrf_token(),
        form_data=form_data,
        errors=errors,
    )


@app.route("/reference/<token>", methods=["GET", "POST"])
def reference_by_token(token):
    with closing(get_connection()) as connection:
        request_row = connection.execute("""
            SELECT * FROM reference_requests
            WHERE token = ?
        """, (token,)).fetchone()

    if request_row is None:
        return "Invalid reference link.", 404

    if request_row["status"] == "completed":
        return "This reference has already been submitted.", 403

    if request.method == "POST":
        validate_csrf_token()

        form_data = get_reference_form_data()
        for locked_field in (
            "candidate_name",
            "referee_name",
            "referee_email",
            "organisation",
            "job_title",
        ):
            form_data[locked_field] = request_row[locked_field] or ""

        errors = validate_reference(form_data)

        if errors:
            return render_template(
                "index.html",
                csrf_token=generate_csrf_token(),
                form_data=form_data,
                errors=errors,
                token=token,
            ), 400

        with closing(get_connection()) as connection:
            with connection:
                connection.execute("""
                    INSERT INTO references_table (
                        request_id,
                        candidate_name,
                        referee_name,
                        referee_email,
                        organisation,
                        job_title,
                        relationship,
                        start_date,
                        end_date,
                        rehire,
                        clinical_competence,
                        communication_skills,
                        professional_conduct,
                        reference_text,
                        signature,
                        token,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    request_row["id"],
                    form_data["candidate_name"],
                    form_data["referee_name"],
                    form_data["referee_email"],
                    form_data["organisation"],
                    form_data["job_title"],
                    form_data["relationship"],
                    form_data["start_date"],
                    form_data["end_date"],
                    form_data["rehire"],
                    form_data["clinical_competence"],
                    form_data["communication_skills"],
                    form_data["professional_conduct"],
                    form_data["reference_text"],
                    form_data["signature"],
                    token,
                    "completed",
                ))

                connection.execute("""
                    UPDATE reference_requests
                    SET status = 'completed',
                        submitted_at = CURRENT_TIMESTAMP
                    WHERE token = ?
                """, (token,))

        return render_template("submitted.html")

    prefilled_data = {
        "candidate_name": request_row["candidate_name"],
        "referee_name": request_row["referee_name"],
        "referee_email": request_row["referee_email"],
        "organisation": request_row["organisation"] or "",
        "job_title": request_row["job_title"] or "",
    }

    return render_template(
        "index.html",
        csrf_token=generate_csrf_token(),
        form_data=prefilled_data,
        errors=[],
        token=token,
    )


@app.route("/submit", methods=["GET", "POST"])
def submit():
    return "Public submissions are disabled. Use a secure reference link.", 403


@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "")

    with closing(get_connection()) as connection:
        total_references = connection.execute(
            "SELECT COUNT(*) FROM references_table"
        ).fetchone()[0]

        pending_requests = connection.execute(
            "SELECT COUNT(*) FROM reference_requests WHERE status = 'pending'"
        ).fetchone()[0]

        completed_requests = connection.execute(
            "SELECT COUNT(*) FROM reference_requests WHERE status = 'completed'"
        ).fetchone()[0]

        rehire_yes = connection.execute(
            "SELECT COUNT(*) FROM references_table WHERE rehire = ?",
            ("Yes",),
        ).fetchone()[0]

        rehire_no = connection.execute(
            "SELECT COUNT(*) FROM references_table WHERE rehire = ?",
            ("No",),
        ).fetchone()[0]

        rehire_reservations = connection.execute(
            "SELECT COUNT(*) FROM references_table WHERE rehire = ?",
            ("With reservations",),
        ).fetchone()[0]

        if search:
            rows = connection.execute("""
                SELECT * FROM references_table
                WHERE candidate_name LIKE ?
                ORDER BY submitted_at DESC
            """, (f"%{search}%",)).fetchall()
        else:
            rows = connection.execute("""
                SELECT * FROM references_table
                ORDER BY submitted_at DESC
            """).fetchall()

        requests = connection.execute("""
            SELECT * FROM reference_requests
            ORDER BY created_at DESC
        """).fetchall()

    return render_template(
        "dashboard.html",
        total_references=total_references,
        pending_requests=pending_requests,
        completed_requests=completed_requests,
        rehire_yes=rehire_yes,
        rehire_no=rehire_no,
        rehire_reservations=rehire_reservations,
        rows=rows,
        requests=requests,
        search=search,
    )


@app.route("/database-view")
@login_required
def database_view():
    search = request.args.get("search", "").strip()

    with closing(get_connection()) as connection:
        if search:
            rows = connection.execute("""
                SELECT * FROM references_table
                WHERE candidate_name LIKE ?
                ORDER BY submitted_at DESC
            """, (f"%{search}%",)).fetchall()
        else:
            rows = connection.execute("""
                SELECT * FROM references_table
                ORDER BY submitted_at DESC
            """).fetchall()

    return render_template("database_view.html", rows=rows, search=search)


if __name__ == "__main__":
    init_database()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
