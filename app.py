import os
import secrets
import sqlite3
import logging
from contextlib import closing
from functools import wraps
from pathlib import Path
from datetime import timedelta
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from services.email_service import (
    send_reference_completed_notification,
    send_reference_invitation,
    send_reference_request_receipt,
)

app = Flask(__name__)

# Development fallback only. Set SECRET_KEY in the environment for production.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    str(Path(__file__).with_name("references.db")),
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
    in {"1", "true", "yes", "on"}
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

RATING_OPTIONS = {"Excellent", "Good", "Satisfactory", "Poor"}
REHIRE_OPTIONS = {"Yes", "No", "With reservations"}
REFERENCE_TYPES = {"full_reference", "employment_statement"}
EMPLOYMENT_TYPES = {"Full-time", "Part-time", "Temporary", "Agency", "Contract", "Other"}

logger = logging.getLogger(__name__)


def get_connection():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


def get_table_columns(connection, table_name):
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def ensure_column(connection, table_name, column_name, column_sql):
    columns = get_table_columns(connection, table_name)
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf_token():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(400)
    session.pop("csrf_token", None)


def safe_next_url(next_url):
    if not next_url:
        return None
    parsed = urlsplit(next_url)
    if parsed.scheme or parsed.netloc:
        return None
    if not next_url.startswith("/") or next_url.startswith("//"):
        return None
    return next_url


def admin_password():
    # Local development fallback. Set ADMIN_PASSWORD in production.
    return os.environ.get("ADMIN_PASSWORD", "changeme")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("logged_in") is not True:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped_view


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.path in ("/dashboard", "/database-view", "/create-request") or (
        request.path.startswith("/reference-request/")
    ) or (
        request.path.startswith("/references/") and request.path.endswith("/export-pdf")
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    return response


def admin_notification_email():
    return os.environ.get("ADMIN_NOTIFICATION_EMAIL") or os.environ.get("SMTP_USERNAME")


def ensure_database_schema():
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
                    status TEXT NOT NULL DEFAULT 'sent',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    submitted_at TIMESTAMP,
                    sent_at TIMESTAMP,
                    opened_at TIMESTAMP,
                    completed_at TIMESTAMP
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
                    reference_type TEXT,
                    employment_type TEXT,
                    statement_text TEXT,
                    accuracy_confirmed INTEGER DEFAULT 0,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (request_id) REFERENCES reference_requests (id)
                )
            """)

            ensure_column(connection, "reference_requests", "organisation", "organisation TEXT")
            ensure_column(connection, "reference_requests", "job_title", "job_title TEXT")
            ensure_column(connection, "reference_requests", "token", "token TEXT")
            ensure_column(connection, "reference_requests", "status", "status TEXT DEFAULT 'sent'")
            ensure_column(connection, "reference_requests", "created_at", "created_at TIMESTAMP")
            ensure_column(connection, "reference_requests", "submitted_at", "submitted_at TIMESTAMP")
            ensure_column(connection, "reference_requests", "sent_at", "sent_at TIMESTAMP")
            ensure_column(connection, "reference_requests", "opened_at", "opened_at TIMESTAMP")
            ensure_column(connection, "reference_requests", "completed_at", "completed_at TIMESTAMP")

            ensure_column(connection, "references_table", "request_id", "request_id INTEGER")
            ensure_column(connection, "references_table", "organisation", "organisation TEXT")
            ensure_column(connection, "references_table", "job_title", "job_title TEXT")
            ensure_column(connection, "references_table", "token", "token TEXT")
            ensure_column(connection, "references_table", "status", "status TEXT DEFAULT 'completed'")
            ensure_column(connection, "references_table", "submitted_at", "submitted_at TIMESTAMP")
            ensure_column(connection, "references_table", "reference_type", "reference_type TEXT")
            ensure_column(connection, "references_table", "employment_type", "employment_type TEXT")
            ensure_column(connection, "references_table", "statement_text", "statement_text TEXT")
            ensure_column(connection, "references_table", "accuracy_confirmed", "accuracy_confirmed INTEGER DEFAULT 0")
            ensure_column(connection, "references_table", "completed_at", "completed_at TIMESTAMP")

            connection.execute("""
                UPDATE reference_requests
                SET status = 'sent'
                WHERE status = 'pending'
            """)
            connection.execute("""
                UPDATE reference_requests
                SET sent_at = COALESCE(sent_at, created_at, CURRENT_TIMESTAMP)
                WHERE status IN ('sent', 'opened', 'completed')
            """)
            connection.execute("""
                UPDATE reference_requests
                SET completed_at = COALESCE(completed_at, submitted_at)
                WHERE status = 'completed'
            """)
            connection.execute("""
                UPDATE references_table
                SET reference_type = COALESCE(reference_type, 'full_reference'),
                    completed_at = COALESCE(completed_at, submitted_at)
                WHERE reference_type IS NULL
            """)

            connection.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_reference_requests_token
                ON reference_requests (token)
                WHERE token IS NOT NULL
            """)


def init_database():
    ensure_database_schema()


def get_reference_form_data():
    fields = [
        "reference_type",
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
        "employment_type",
        "statement_text",
        "signature",
    ]
    data = {field: request.form.get(field, "").strip() for field in fields}
    data["accuracy_confirmed"] = "1" if request.form.get("accuracy_confirmed") else ""
    return data


def validate_reference(data):
    errors = []
    reference_type = data.get("reference_type")

    if reference_type not in REFERENCE_TYPES:
        errors.append("Response type is required.")
        return errors

    required_fields = [
        "candidate_name",
        "referee_name",
        "referee_email",
        "organisation",
        "job_title",
        "start_date",
        "end_date",
        "signature",
    ]

    if reference_type == "full_reference":
        required_fields.extend([
            "relationship",
            "rehire",
            "clinical_competence",
            "communication_skills",
            "professional_conduct",
            "reference_text",
        ])
    else:
        required_fields.extend([
            "employment_type",
            "statement_text",
            "accuracy_confirmed",
        ])

    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field.replace('_', ' ').title()} is required.")

    if reference_type == "full_reference" and data["rehire"] not in REHIRE_OPTIONS:
        errors.append("Rehire must be a valid option.")

    if reference_type == "full_reference":
        for field in (
            "clinical_competence",
            "communication_skills",
            "professional_conduct",
        ):
            if data[field] not in RATING_OPTIONS:
                errors.append(f"{field.replace('_', ' ').title()} must be a valid rating.")

    if reference_type == "employment_statement":
        if data["employment_type"] and data["employment_type"] not in EMPLOYMENT_TYPES:
            errors.append("Employment Type must be a valid option.")
        if data["accuracy_confirmed"] != "1":
            errors.append("Accuracy confirmation is required.")

    if data["start_date"] and data["end_date"] and data["start_date"] > data["end_date"]:
        errors.append("Employment start date cannot be after employment end date.")

    if len(data.get("reference_text", "")) > 5000:
        errors.append("Reference comments must be 5,000 characters or fewer.")

    if len(data.get("statement_text", "")) > 5000:
        errors.append("Statement of employment must be 5,000 characters or fewer.")

    return errors


def reference_type_label(reference_type):
    if reference_type == "employment_statement":
        return "Statement of Employment"
    return "Full Reference"


def send_admin_request_email(form_data, sent_at, secure_link, invitation_sent):
    admin_email = admin_notification_email()
    if not admin_email:
        logger.info("Admin request notification skipped because no admin email is configured.")
        return

    try:
        send_reference_request_receipt(
            admin_email,
            form_data["candidate_name"],
            form_data["referee_name"],
            form_data["referee_email"],
            form_data["organisation"],
            sent_at,
            secure_link,
            url_for("dashboard", _external=True),
            invitation_sent=invitation_sent,
        )
    except Exception:
        logger.exception("Admin request notification failed.")


def send_admin_completion_email(form_data, completed_at, reference_type):
    admin_email = admin_notification_email()
    if not admin_email:
        logger.info("Admin completion notification skipped because no admin email is configured.")
        return

    try:
        send_reference_completed_notification(
            admin_email,
            form_data["candidate_name"],
            form_data["referee_name"],
            form_data["referee_email"],
            form_data["organisation"],
            reference_type,
            completed_at,
            url_for("dashboard", _external=True),
        )
    except Exception:
        logger.exception("Admin completion notification failed.")


@app.route("/")
def home():
    if session.get("logged_in") is True:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    errors = []

    if request.method == "POST":
        validate_csrf_token()

        password = request.form.get("password", "")
        expected_password = admin_password()

        if secrets.compare_digest(password, expected_password):
            next_url = safe_next_url(request.args.get("next"))
            session.clear()
            session["logged_in"] = True
            session.permanent = True
            generate_csrf_token()
            return redirect(next_url or url_for("dashboard"))

        errors.append("Invalid password.")

    return render_template(
        "login.html",
        csrf_token=generate_csrf_token(),
        errors=errors,
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # TODO: Remove GET logout after all navigation uses the POST form.
    if request.method == "POST":
        validate_csrf_token()
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
                    cursor = connection.execute("""
                        INSERT INTO reference_requests (
                            candidate_name,
                            referee_name,
                            referee_email,
                            organisation,
                            job_title,
                            token,
                            status,
                            sent_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        form_data["candidate_name"],
                        form_data["referee_name"],
                        form_data["referee_email"],
                        form_data["organisation"],
                        form_data["job_title"],
                        token,
                        "sent",
                    ))
                    request_id = cursor.lastrowid
                    sent_at = connection.execute("""
                        SELECT sent_at FROM reference_requests WHERE id = ?
                    """, (request_id,)).fetchone()["sent_at"]

            secure_link = url_for("reference_by_token", token=token, _external=True)
            email_sent = True

            try:
                send_reference_invitation(
                    form_data["referee_name"],
                    form_data["referee_email"],
                    form_data["candidate_name"],
                    secure_link,
                )
            except Exception:
                email_sent = False

            send_admin_request_email(form_data, sent_at, secure_link, email_sent)

            return render_template(
                "request_created.html",
                request_id=request_id,
                secure_link=secure_link,
                email_sent=email_sent,
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

    if request.method == "GET" and request_row["status"] == "sent":
        with closing(get_connection()) as connection:
            with connection:
                connection.execute("""
                    UPDATE reference_requests
                    SET status = 'opened',
                        opened_at = COALESCE(opened_at, CURRENT_TIMESTAMP)
                    WHERE token = ?
                      AND status = 'sent'
                """, (token,))
                request_row = connection.execute("""
                    SELECT * FROM reference_requests
                    WHERE token = ?
                """, (token,)).fetchone()

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
                employment_types=sorted(EMPLOYMENT_TYPES),
            ), 400

        with closing(get_connection()) as connection:
            with connection:
                current_request = connection.execute("""
                    SELECT * FROM reference_requests
                    WHERE token = ?
                """, (token,)).fetchone()
                if current_request is None:
                    return "Invalid reference link.", 404
                if current_request["status"] == "completed":
                    return "This reference has already been submitted.", 403

                reference_type = form_data["reference_type"]
                relationship = form_data["relationship"] if reference_type == "full_reference" else ""
                rehire = form_data["rehire"] if reference_type == "full_reference" else ""
                clinical_competence = form_data["clinical_competence"] if reference_type == "full_reference" else ""
                communication_skills = form_data["communication_skills"] if reference_type == "full_reference" else ""
                professional_conduct = form_data["professional_conduct"] if reference_type == "full_reference" else ""
                reference_text = form_data["reference_text"] if reference_type == "full_reference" else ""
                employment_type = form_data["employment_type"] if reference_type == "employment_statement" else None
                statement_text = form_data["statement_text"] if reference_type == "employment_statement" else None
                accuracy_confirmed = 1 if reference_type == "employment_statement" else 0

                update_cursor = connection.execute("""
                    UPDATE reference_requests
                    SET status = 'completed',
                        submitted_at = CURRENT_TIMESTAMP,
                        completed_at = CURRENT_TIMESTAMP
                    WHERE token = ?
                      AND status != 'completed'
                """, (token,))
                if update_cursor.rowcount != 1:
                    return "This reference has already been submitted.", 403

                completed_at = connection.execute("""
                    SELECT completed_at FROM reference_requests WHERE token = ?
                """, (token,)).fetchone()["completed_at"]

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
                        status,
                        reference_type,
                        employment_type,
                        statement_text,
                        accuracy_confirmed,
                        completed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    request_row["id"],
                    form_data["candidate_name"],
                    form_data["referee_name"],
                    form_data["referee_email"],
                    form_data["organisation"],
                    form_data["job_title"],
                    relationship,
                    form_data["start_date"],
                    form_data["end_date"],
                    rehire,
                    clinical_competence,
                    communication_skills,
                    professional_conduct,
                    reference_text,
                    form_data["signature"],
                    token,
                    "completed",
                    reference_type,
                    employment_type,
                    statement_text,
                    accuracy_confirmed,
                    completed_at,
                ))

        send_admin_completion_email(form_data, completed_at, form_data["reference_type"])

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
        employment_types=sorted(EMPLOYMENT_TYPES),
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
            "SELECT COUNT(*) FROM reference_requests WHERE status IN ('sent', 'opened')"
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

        recent_completed = connection.execute("""
            SELECT * FROM references_table
            ORDER BY submitted_at DESC
            LIMIT 5
        """).fetchall()

        recent_pending = connection.execute("""
            SELECT * FROM reference_requests
            WHERE status IN ('sent', 'opened')
            ORDER BY created_at DESC
            LIMIT 5
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
        recent_completed=recent_completed,
        recent_pending=recent_pending,
        requests=requests,
        search=search,
        csrf_token=generate_csrf_token(),
    )


@app.route("/reference-request/<int:request_id>/resend-email", methods=["POST"])
@login_required
def resend_reference_email(request_id):
    validate_csrf_token()

    with closing(get_connection()) as connection:
        request_row = connection.execute("""
            SELECT * FROM reference_requests
            WHERE id = ?
        """, (request_id,)).fetchone()

    if request_row is None:
        abort(404)

    if request_row["status"] == "completed":
        return "Completed reference requests cannot be resent.", 403

    if request_row["status"] not in ("sent", "opened"):
        return "This request cannot be resent.", 400

    if not request_row["token"]:
        return "This request does not have a secure token to resend.", 400

    secure_link = url_for(
        "reference_by_token",
        token=request_row["token"],
        _external=True,
    )
    email_sent = True

    try:
        send_reference_invitation(
            request_row["referee_name"],
            request_row["referee_email"],
            request_row["candidate_name"],
            secure_link,
        )
    except Exception:
        email_sent = False

    return render_template(
        "request_created.html",
        request_id=request_row["id"],
        secure_link=secure_link,
        email_sent=email_sent,
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

    return render_template(
        "database_view.html",
        rows=rows,
        search=search,
        csrf_token=generate_csrf_token(),
    )


@app.route("/references/<int:reference_id>/export-pdf")
@login_required
def export_reference_pdf(reference_id):
    # TODO: Generate a branded PDF once a PDF library/export template is selected.
    with closing(get_connection()) as connection:
        row = connection.execute("""
            SELECT id FROM references_table
            WHERE id = ?
        """, (reference_id,)).fetchone()

    if row is None:
        abort(404)

    return "PDF export coming soon.", 501


if __name__ == "__main__":
    init_database()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
