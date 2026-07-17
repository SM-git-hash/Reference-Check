import os
import secrets
import sqlite3
import logging
import hashlib
import re
import shutil
import mimetypes
import uuid
from io import BytesIO
from contextlib import closing
from functools import wraps
from pathlib import Path
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
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
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

RATING_OPTIONS = {"Excellent", "Good", "Satisfactory", "Poor"}
REHIRE_OPTIONS = {"Yes", "No", "With reservations"}
REFERENCE_TYPES = {"full_reference", "employment_statement"}
EMPLOYMENT_TYPES = {"Full-time", "Part-time", "Temporary", "Agency", "Contract", "Other"}
PUBLIC_EMAIL_DOMAINS = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com", "live.com"}
ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
ALLOWED_UPLOAD_MIME_TYPES = {"application/pdf", "image/jpeg", "image/png"}
ROLES = {"super_admin", "organisation_admin", "recruiter"}
EVENT_TYPES = {
    "request_created",
    "invitation_email_sent",
    "invitation_email_failed",
    "link_opened",
    "reference_started",
    "reference_completed",
    "admin_notification_sent",
    "admin_notification_failed",
    "reference_downloaded",
    "resend_email_sent",
    "resend_email_failed",
    "verification_document_uploaded",
    "verification_document_viewed",
    "verification_document_downloaded",
    "verification_document_accepted",
    "verification_document_rejected",
    "pdf_downloaded",
    "super_admin_sensitive_record_accessed",
}
PLATFORM_EVENT_TYPES = {
    "organisation_created",
    "organisation_updated",
    "organisation_suspended",
    "organisation_reactivated",
    "recruiter_created",
    "recruiter_deactivated",
    "recruiter_reactivated",
    "login_success",
    "login_failure",
    "logout",
    "account_locked",
    "super_admin_sensitive_record_accessed",
}

logger = logging.getLogger(__name__)
_BACKED_UP_DATABASES = set()


def get_connection():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


def private_upload_root():
    root = Path(app.instance_path) / "private_uploads" / "reference_verification"
    root.mkdir(parents=True, exist_ok=True)
    return root


def backup_database_before_multitenancy():
    database_path = Path(app.config["DATABASE"])
    if not database_path.exists() or database_path.stat().st_size == 0:
        return None
    if str(database_path) in _BACKED_UP_DATABASES:
        return None
    try:
        with closing(sqlite3.connect(database_path)) as connection:
            has_orgs = connection.execute("""
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name = 'organisations'
            """).fetchone()
        if has_orgs:
            return None
        backup_dir = Path(app.instance_path) / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"references_before_multitenancy_{timestamp}.db"
        shutil.copy2(database_path, backup_path)
        _BACKED_UP_DATABASES.add(str(database_path))
        app.config["LAST_DATABASE_BACKUP"] = str(backup_path)
        return backup_path
    except Exception:
        logger.exception("Failed to create pre-multitenancy database backup.")
        return None


def get_table_columns(connection, table_name):
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def ensure_column(connection, table_name, column_name, column_sql):
    columns = get_table_columns(connection, table_name)
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def email_domain(email_address):
    if not email_address or "@" not in email_address:
        return "unknown"
    return email_address.rsplit("@", 1)[1].lower()


def mask_email(email_address):
    if not email_address or "@" not in email_address:
        return "unknown"
    local, domain = email_address.rsplit("@", 1)
    if not local:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"


def sanitize_event_details(event_details):
    if event_details is None:
        return None
    details = str(event_details)
    details = re.sub(r"(token=)[A-Za-z0-9_\-]+", r"\1[redacted]", details, flags=re.IGNORECASE)
    details = re.sub(r"(/reference/)[A-Za-z0-9_\-]+", r"\1[redacted]", details)
    for secret_name in ("SMTP_PASSWORD", "SMTP_USERNAME", "SECRET_KEY", "ADMIN_PASSWORD"):
        secret_value = os.environ.get(secret_name)
        if secret_value:
            details = details.replace(secret_value, "[redacted]")
    return details[:500]


def current_actor_metadata():
    try:
        user = getattr(g, "current_user", None)
    except RuntimeError:
        user = None
    if not user:
        return None, None, None
    return user["id"], user["role"], user["organisation_id"]


def safe_failure_category(exc):
    name = exc.__class__.__name__
    if "config" in name.lower():
        return "Email configuration error"
    if "auth" in name.lower() or "login" in str(exc).lower():
        return "Email authentication error"
    if "timeout" in name.lower() or "timeout" in str(exc).lower():
        return "Email server timeout"
    return "Email send error"


def record_reference_event(
    request_id: int,
    event_type: str,
    event_label: str,
    event_details: str | None = None,
    connection=None,
    actor_user_id=None,
    actor_role=None,
    organisation_id=None,
):
    if event_type not in EVENT_TYPES:
        logger.warning("Skipped unknown reference event type %s", event_type)
        return

    details = sanitize_event_details(event_details)
    if actor_user_id is None and actor_role is None and organisation_id is None:
        actor_user_id, actor_role, organisation_id = current_actor_metadata()
    owns_connection = connection is None

    try:
        if owns_connection:
            with closing(get_connection()) as event_connection:
                with event_connection:
                    event_connection.execute("""
                        INSERT INTO reference_events (
                            request_id,
                            event_type,
                            event_label,
                            event_details,
                            actor_user_id,
                            actor_role,
                            organisation_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (request_id, event_type, event_label, details, actor_user_id, actor_role, organisation_id))
        else:
            connection.execute("""
                INSERT INTO reference_events (
                    request_id,
                    event_type,
                    event_label,
                    event_details,
                    actor_user_id,
                    actor_role,
                    organisation_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (request_id, event_type, event_label, details, actor_user_id, actor_role, organisation_id))
    except Exception:
        logger.exception("Reference audit event failed for request_id=%s type=%s", request_id, event_type)


def record_platform_event(
    event_type,
    event_label,
    event_details=None,
    organisation_id=None,
    actor_user_id=None,
    actor_role=None,
    connection=None,
):
    if event_type not in PLATFORM_EVENT_TYPES:
        logger.warning("Skipped unknown platform event type %s", event_type)
        return
    if actor_user_id is None and actor_role is None:
        actor_user_id, actor_role, current_org_id = current_actor_metadata()
        organisation_id = organisation_id if organisation_id is not None else current_org_id
    details = sanitize_event_details(event_details)
    owns_connection = connection is None
    try:
        if owns_connection:
            with closing(get_connection()) as event_connection:
                with event_connection:
                    event_connection.execute("""
                        INSERT INTO platform_events (
                            event_type, event_label, event_details,
                            actor_user_id, actor_role, organisation_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (event_type, event_label, details, actor_user_id, actor_role, organisation_id))
        else:
            connection.execute("""
                INSERT INTO platform_events (
                    event_type, event_label, event_details,
                    actor_user_id, actor_role, organisation_id
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (event_type, event_label, details, actor_user_id, actor_role, organisation_id))
    except Exception:
        logger.exception("Platform audit event failed for type=%s", event_type)


def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf_token():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(400)
    session.pop("csrf_token", None)


def validate_public_csrf_header():
    token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(400)


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


def admin_email():
    return os.environ.get("ADMIN_EMAIL", "admin@referencebridge.local").strip().lower()


def get_user_by_id(user_id):
    if not user_id:
        return None
    with closing(get_connection()) as connection:
        return connection.execute("""
            SELECT
                u.*,
                o.name AS organisation_name,
                o.slug AS organisation_slug,
                o.status AS organisation_status
            FROM users u
            LEFT JOIN organisations o ON o.id = u.organisation_id
            WHERE u.id = ?
        """, (user_id,)).fetchone()


def get_user_by_email(email):
    with closing(get_connection()) as connection:
        return connection.execute("""
            SELECT
                u.*,
                o.name AS organisation_name,
                o.slug AS organisation_slug,
                o.status AS organisation_status
            FROM users u
            LEFT JOIN organisations o ON o.id = u.organisation_id
            WHERE lower(u.email) = lower(?)
        """, (email,)).fetchone()


def user_is_active(user):
    if not user or user["status"] != "active":
        return False
    if user["role"] != "super_admin" and user["organisation_status"] != "active":
        return False
    return True


@app.before_request
def load_current_user():
    g.current_user = None
    user_id = session.get("user_id")
    if user_id:
        g.current_user = get_user_by_id(user_id)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not user_is_active(getattr(g, "current_user", None)):
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped_view


def require_role(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            if g.current_user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


def current_user_can_access_org(organisation_id):
    user = getattr(g, "current_user", None)
    if not user:
        return False
    if user["role"] == "super_admin":
        return True
    return organisation_id is not None and user["organisation_id"] == organisation_id


def scoped_org_condition(alias="rr"):
    user = g.current_user
    if user["role"] == "super_admin":
        return "", []
    return f" AND {alias}.organisation_id = ?", [user["organisation_id"]]


def get_request_for_current_user_or_404(request_id):
    with closing(get_connection()) as connection:
        if g.current_user["role"] == "super_admin":
            row = connection.execute("SELECT * FROM reference_requests WHERE id = ?", (request_id,)).fetchone()
        else:
            row = connection.execute("""
                SELECT * FROM reference_requests
                WHERE id = ? AND organisation_id = ?
            """, (request_id, g.current_user["organisation_id"])).fetchone()
    if row is None:
        abort(404)
    return row


def get_reference_for_current_user_or_404(reference_id):
    with closing(get_connection()) as connection:
        if g.current_user["role"] == "super_admin":
            row = connection.execute("""
                SELECT rt.*, rr.organisation_id, rr.sent_at, rr.opened_at,
                       rr.completed_at AS request_completed_at, rr.id AS audit_request_id
                FROM references_table rt
                LEFT JOIN reference_requests rr ON rr.id = rt.request_id
                WHERE rt.id = ?
            """, (reference_id,)).fetchone()
        else:
            row = connection.execute("""
                SELECT rt.*, rr.organisation_id, rr.sent_at, rr.opened_at,
                       rr.completed_at AS request_completed_at, rr.id AS audit_request_id
                FROM references_table rt
                JOIN reference_requests rr ON rr.id = rt.request_id
                WHERE rt.id = ? AND rr.organisation_id = ?
            """, (reference_id, g.current_user["organisation_id"])).fetchone()
    if row is None:
        abort(404)
    return row


def get_verification_document_for_current_user_or_404(document_id):
    with closing(get_connection()) as connection:
        if g.current_user["role"] == "super_admin":
            row = connection.execute("""
                SELECT vd.*, rr.organisation_id, rr.candidate_name
                FROM reference_verification_documents vd
                JOIN reference_requests rr ON rr.id = vd.request_id
                WHERE vd.id = ?
            """, (document_id,)).fetchone()
        else:
            row = connection.execute("""
                SELECT vd.*, rr.organisation_id, rr.candidate_name
                FROM reference_verification_documents vd
                JOIN reference_requests rr ON rr.id = vd.request_id
                WHERE vd.id = ? AND rr.organisation_id = ?
            """, (document_id, g.current_user["organisation_id"])).fetchone()
    if row is None:
        abort(404)
    return row


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.path in ("/dashboard", "/database-view", "/create-request") or (
        request.path.startswith("/super-admin")
    ) or (
        request.path.startswith("/verification-document/")
    ) or (
        request.path.startswith("/reference-request/")
    ) or (
        request.path.startswith("/references/") and request.path.endswith("/export-pdf")
    ) or (
        re.match(r"^/reference/\d+/(view|pdf)$", request.path)
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    return response


def admin_notification_email():
    return os.environ.get("ADMIN_NOTIFICATION_EMAIL") or os.environ.get("SMTP_USERNAME")


def ensure_database_schema():
    backup_database_before_multitenancy()
    with closing(get_connection()) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS organisations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    slug TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'active',
                    primary_contact_name TEXT,
                    primary_contact_email TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP,
                    suspended_at TIMESTAMP,
                    data_retention_days INTEGER,
                    subscription_plan TEXT DEFAULT 'trial'
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organisation_id INTEGER,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TIMESTAMP,
                    password_changed_at TIMESTAMP,
                    failed_login_count INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    FOREIGN KEY (organisation_id) REFERENCES organisations(id)
                )
            """)

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
                    completed_at TIMESTAMP,
                    organisation_id INTEGER,
                    created_by_user_id INTEGER,
                    FOREIGN KEY (organisation_id) REFERENCES organisations(id),
                    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
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
                    signer_name TEXT,
                    signer_job_title TEXT,
                    signer_organisation TEXT,
                    electronic_signature TEXT,
                    signed_at TIMESTAMP,
                    declaration_confirmed INTEGER DEFAULT 0,
                    signature_ip_hash TEXT,
                    signature_user_agent_summary TEXT,
                    FOREIGN KEY (request_id) REFERENCES reference_requests (id)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS reference_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    event_type TEXT NOT NULL,
                    event_label TEXT NOT NULL,
                    event_details TEXT,
                    actor_user_id INTEGER,
                    actor_role TEXT,
                    organisation_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (request_id) REFERENCES reference_requests(id),
                    FOREIGN KEY (actor_user_id) REFERENCES users(id),
                    FOREIGN KEY (organisation_id) REFERENCES organisations(id)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS platform_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_label TEXT NOT NULL,
                    event_details TEXT,
                    actor_user_id INTEGER,
                    actor_role TEXT,
                    organisation_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (actor_user_id) REFERENCES users(id),
                    FOREIGN KEY (organisation_id) REFERENCES organisations(id)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS reference_verification_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL UNIQUE,
                    mime_type TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    uploaded_by_role TEXT NOT NULL,
                    review_status TEXT NOT NULL DEFAULT 'not_reviewed',
                    reviewed_by_user_id INTEGER,
                    reviewed_at TIMESTAMP,
                    review_notes TEXT,
                    FOREIGN KEY (request_id) REFERENCES reference_requests(id),
                    FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
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
            ensure_column(connection, "reference_requests", "organisation_id", "organisation_id INTEGER")
            ensure_column(connection, "reference_requests", "created_by_user_id", "created_by_user_id INTEGER")

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
            ensure_column(connection, "references_table", "signer_name", "signer_name TEXT")
            ensure_column(connection, "references_table", "signer_job_title", "signer_job_title TEXT")
            ensure_column(connection, "references_table", "signer_organisation", "signer_organisation TEXT")
            ensure_column(connection, "references_table", "electronic_signature", "electronic_signature TEXT")
            ensure_column(connection, "references_table", "signed_at", "signed_at TIMESTAMP")
            ensure_column(connection, "references_table", "declaration_confirmed", "declaration_confirmed INTEGER DEFAULT 0")
            ensure_column(connection, "references_table", "signature_ip_hash", "signature_ip_hash TEXT")
            ensure_column(connection, "references_table", "signature_user_agent_summary", "signature_user_agent_summary TEXT")

            ensure_column(connection, "reference_events", "actor_user_id", "actor_user_id INTEGER")
            ensure_column(connection, "reference_events", "actor_role", "actor_role TEXT")
            ensure_column(connection, "reference_events", "organisation_id", "organisation_id INTEGER")

            connection.execute("""
                INSERT OR IGNORE INTO organisations (
                    name, slug, status, primary_contact_email, subscription_plan, created_at
                )
                VALUES (?, ?, 'active', ?, 'internal', CURRENT_TIMESTAMP)
            """, ("ReferenceBridge Internal", "referencebridge-internal", admin_email()))

            default_org = connection.execute("""
                SELECT id FROM organisations WHERE slug = ?
            """, ("referencebridge-internal",)).fetchone()
            default_org_id = default_org["id"]

            connection.execute("""
                INSERT OR IGNORE INTO users (
                    organisation_id, email, password_hash, first_name, last_name,
                    role, status, created_at, password_changed_at
                )
                VALUES (?, ?, ?, ?, ?, 'super_admin', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                default_org_id,
                admin_email(),
                generate_password_hash(admin_password()),
                "Platform",
                "Admin",
            ))

            default_user = connection.execute("""
                SELECT id FROM users WHERE lower(email) = lower(?)
            """, (admin_email(),)).fetchone()
            default_user_id = default_user["id"]

            connection.execute("""
                UPDATE reference_requests
                SET organisation_id = ?
                WHERE organisation_id IS NULL
            """, (default_org_id,))
            connection.execute("""
                UPDATE reference_requests
                SET created_by_user_id = ?
                WHERE created_by_user_id IS NULL
            """, (default_user_id,))
            connection.execute("""
                UPDATE reference_events
                SET organisation_id = (
                    SELECT organisation_id FROM reference_requests
                    WHERE reference_requests.id = reference_events.request_id
                )
                WHERE organisation_id IS NULL AND request_id IS NOT NULL
            """)

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
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_reference_events_request_created
                ON reference_events (request_id, created_at)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_reference_requests_org_status
                ON reference_requests (organisation_id, status)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_reference_requests_created_by
                ON reference_requests (created_by_user_id)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_org_role
                ON users (organisation_id, role)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_verification_docs_request_status
                ON reference_verification_documents (request_id, review_status)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_platform_events_org_created
                ON platform_events (organisation_id, created_at)
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
        "signer_name",
        "signer_job_title",
        "signer_organisation",
        "electronic_signature",
    ]
    data = {field: request.form.get(field, "").strip() for field in fields}
    data["accuracy_confirmed"] = "1" if request.form.get("accuracy_confirmed") else ""
    data["declaration_confirmed"] = "1" if request.form.get("declaration_confirmed") else ""
    if not data["signer_name"]:
        data["signer_name"] = data["referee_name"]
    if not data["signer_job_title"]:
        data["signer_job_title"] = data["job_title"]
    if not data["signer_organisation"]:
        data["signer_organisation"] = data["organisation"]
    if not data["electronic_signature"]:
        data["electronic_signature"] = data["signature"]
    if not data["signature"]:
        data["signature"] = data["electronic_signature"]
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
        "signer_name",
        "signer_job_title",
        "signer_organisation",
        "electronic_signature",
        "declaration_confirmed",
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


def is_public_email(email_address):
    return email_domain(email_address) in PUBLIC_EMAIL_DOMAINS


def signature_ip_hash():
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if not ip_address:
        return None
    salt = os.environ.get("SIGNATURE_IP_HASH_SALT") or app.config["SECRET_KEY"]
    # Privacy note: this supports duplicate/forensic checks without storing a raw IP address.
    return hashlib.sha256(f"{salt}:{ip_address}".encode("utf-8")).hexdigest()


def user_agent_summary():
    value = request.headers.get("User-Agent", "")
    if not value:
        return None
    return value[:160]


def detect_file_mime(content):
    if content.startswith(b"%PDF"):
        return "application/pdf"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    return None


def prepare_verification_upload(upload, consent_given):
    if upload is None or not upload.filename:
        return None, []

    errors = []
    original_filename = secure_filename(upload.filename)
    if not original_filename:
        errors.append("Verification document filename is invalid.")
        return None, errors
    extension = Path(original_filename).suffix.lower()
    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        errors.append("Verification document must be a PDF, JPG, JPEG or PNG file.")
    if not consent_given:
        errors.append("Consent is required when uploading a verification document.")

    content = upload.read()
    upload.seek(0)
    file_size = len(content)
    if file_size > app.config["MAX_CONTENT_LENGTH"]:
        errors.append("Verification document must be 5 MB or smaller.")
    detected_mime = detect_file_mime(content)
    declared_mime = (upload.mimetype or mimetypes.guess_type(original_filename)[0] or "").lower()
    if declared_mime not in ALLOWED_UPLOAD_MIME_TYPES or detected_mime not in ALLOWED_UPLOAD_MIME_TYPES:
        errors.append("Verification document type is not allowed.")
    if detected_mime and declared_mime != detected_mime:
        errors.append("Verification document type does not match its content.")
    if errors:
        return None, errors

    stored_filename = f"{uuid.uuid4().hex}{extension}"
    return {
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "mime_type": detected_mime,
        "file_size": file_size,
        "sha256_hash": hashlib.sha256(content).hexdigest(),
        "content": content,
    }, []


def save_verification_upload(request_id, upload_data, connection):
    if not upload_data:
        return None
    target_path = private_upload_root() / upload_data["stored_filename"]
    target_path.write_bytes(upload_data["content"])
    cursor = connection.execute("""
        INSERT INTO reference_verification_documents (
            request_id,
            original_filename,
            stored_filename,
            mime_type,
            file_size,
            sha256_hash,
            uploaded_by_role,
            review_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'not_reviewed')
    """, (
        request_id,
        upload_data["original_filename"],
        upload_data["stored_filename"],
        upload_data["mime_type"],
        upload_data["file_size"],
        upload_data["sha256_hash"],
        "referee",
    ))
    record_reference_event(
        request_id,
        "verification_document_uploaded",
        "Verification document uploaded",
        f"Filename: {upload_data['original_filename']}; Review status: not_reviewed",
        connection=connection,
    )
    return cursor.lastrowid


def send_admin_request_email(form_data, sent_at, secure_link, invitation_sent):
    admin_email = admin_notification_email()
    if not admin_email:
        logger.info("Admin request notification skipped because no admin email is configured.")
        return False

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
        return False
    return True


def send_admin_completion_email(form_data, completed_at, reference_type):
    admin_email = admin_notification_email()
    if not admin_email:
        logger.info("Admin completion notification skipped because no admin email is configured.")
        return None

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
    except Exception as exc:
        logger.exception("Admin completion notification failed.")
        return False, safe_failure_category(exc)
    return True, None


@app.route("/")
def home():
    if user_is_active(getattr(g, "current_user", None)):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    errors = []

    if request.method == "POST":
        validate_csrf_token()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_user_by_email(email) if email else get_user_by_email(admin_email())

        password_matches = bool(user and check_password_hash(user["password_hash"], password))
        if user and not email and secrets.compare_digest(password, admin_password()):
            password_matches = True

        if user and user_is_active(user) and password_matches:
            if user["role"] != "super_admin" and user["organisation_status"] != "active":
                errors.append("Account is not available.")
                record_platform_event("login_failure", "Login failure", f"Suspended organisation: {email}", organisation_id=user["organisation_id"])
            else:
                next_url = safe_next_url(request.args.get("next"))
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["organisation_id"] = user["organisation_id"]
                session["logged_in"] = True
                session.permanent = True
                with closing(get_connection()) as connection:
                    with connection:
                        connection.execute("""
                            UPDATE users
                            SET last_login_at = CURRENT_TIMESTAMP,
                                failed_login_count = 0
                            WHERE id = ?
                        """, (user["id"],))
                record_platform_event(
                    "login_success",
                    "Login success",
                    f"User: {mask_email(user['email'])}",
                    organisation_id=user["organisation_id"],
                    actor_user_id=user["id"],
                    actor_role=user["role"],
                )
                generate_csrf_token()
                return redirect(next_url or url_for("dashboard"))
        else:
            if user:
                with closing(get_connection()) as connection:
                    with connection:
                        connection.execute("""
                            UPDATE users
                            SET failed_login_count = COALESCE(failed_login_count, 0) + 1
                            WHERE id = ?
                        """, (user["id"],))
            record_platform_event("login_failure", "Login failure", f"Email: {mask_email(email or admin_email())}")

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
    user = getattr(g, "current_user", None)
    if user:
        record_platform_event(
            "logout",
            "Logout",
            f"User: {mask_email(user['email'])}",
            organisation_id=user["organisation_id"],
            actor_user_id=user["id"],
            actor_role=user["role"],
        )
    session.clear()
    return redirect(url_for("login"))


@app.route("/create-request", methods=["GET", "POST"])
@login_required
def create_request():
    if g.current_user["role"] != "super_admin" and g.current_user["organisation_status"] != "active":
        return "Organisation is suspended.", 403
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
                    organisation_id = g.current_user["organisation_id"]
                    if g.current_user["role"] == "super_admin":
                        organisation_id = connection.execute("""
                            SELECT id FROM organisations WHERE slug = ?
                        """, ("referencebridge-internal",)).fetchone()["id"]
                    cursor = connection.execute("""
                        INSERT INTO reference_requests (
                            candidate_name,
                            referee_name,
                            referee_email,
                            organisation,
                            job_title,
                            token,
                            status,
                            sent_at,
                            organisation_id,
                            created_by_user_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                    """, (
                        form_data["candidate_name"],
                        form_data["referee_name"],
                        form_data["referee_email"],
                        form_data["organisation"],
                        form_data["job_title"],
                        token,
                        "sent",
                        organisation_id,
                        g.current_user["id"],
                    ))
                    request_id = cursor.lastrowid
                    sent_at = connection.execute("""
                        SELECT sent_at FROM reference_requests WHERE id = ?
                    """, (request_id,)).fetchone()["sent_at"]
                    record_reference_event(
                        request_id,
                        "request_created",
                        "Request created",
                        (
                            f"Referee email domain: {email_domain(form_data['referee_email'])}; "
                            "Reference types available: Full Employment Reference, Statement of Employment Only"
                        ),
                        connection=connection,
                    )

            secure_link = url_for("reference_by_token", token=token, _external=True)
            email_sent = True

            try:
                send_reference_invitation(
                    form_data["referee_name"],
                    form_data["referee_email"],
                    form_data["candidate_name"],
                    secure_link,
                )
                # Zoho/basic SMTP success confirms server acceptance, not final inbox delivery.
                # TODO: Add webhook-based delivery tracking with a transactional email provider.
                record_reference_event(
                    request_id,
                    "invitation_email_sent",
                    "Invitation email accepted by mail server",
                    f"Recipient: {mask_email(form_data['referee_email'])}",
                )
            except Exception as exc:
                email_sent = False
                record_reference_event(
                    request_id,
                    "invitation_email_failed",
                    "Invitation email failed",
                    safe_failure_category(exc),
                )

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
                update_cursor = connection.execute("""
                    UPDATE reference_requests
                    SET status = 'opened',
                        opened_at = COALESCE(opened_at, CURRENT_TIMESTAMP)
                    WHERE token = ?
                      AND status = 'sent'
                """, (token,))
                if update_cursor.rowcount == 1:
                    record_reference_event(
                        request_row["id"],
                        "link_opened",
                        "Secure link opened",
                        None,
                        connection=connection,
                    )
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
        form_data["referee_email_public"] = is_public_email(form_data["referee_email"])

        errors = validate_reference(form_data)
        upload_data = None
        upload_errors = []
        if is_public_email(form_data["referee_email"]):
            upload_data, upload_errors = prepare_verification_upload(
                request.files.get("verification_document"),
                request.form.get("verification_consent") == "1",
            )
            errors.extend(upload_errors)

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
                        completed_at,
                        signer_name,
                        signer_job_title,
                        signer_organisation,
                        electronic_signature,
                        signed_at,
                        declaration_confirmed,
                        signature_ip_hash,
                        signature_user_agent_summary
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    form_data["signer_name"],
                    form_data["signer_job_title"],
                    form_data["signer_organisation"],
                    form_data["electronic_signature"],
                    completed_at,
                    1 if form_data["declaration_confirmed"] == "1" else 0,
                    signature_ip_hash(),
                    user_agent_summary(),
                ))
                save_verification_upload(request_row["id"], upload_data, connection)
                record_reference_event(
                    request_row["id"],
                    "reference_completed",
                    "Reference completed",
                    reference_type_label(reference_type),
                    connection=connection,
                )

        notification_result = send_admin_completion_email(form_data, completed_at, form_data["reference_type"])
        if notification_result is not None:
            notification_sent, failure_category = notification_result
            if notification_sent:
                record_reference_event(
                    request_row["id"],
                    "admin_notification_sent",
                    "Admin notification sent",
                    f"Reference type: {reference_type_label(form_data['reference_type'])}",
                )
            else:
                record_reference_event(
                    request_row["id"],
                    "admin_notification_failed",
                    "Admin notification failed",
                    failure_category,
                )

        return render_template("submitted.html")

    prefilled_data = {
        "candidate_name": request_row["candidate_name"],
        "referee_name": request_row["referee_name"],
        "referee_email": request_row["referee_email"],
        "organisation": request_row["organisation"] or "",
        "job_title": request_row["job_title"] or "",
        "signer_name": request_row["referee_name"],
        "signer_job_title": request_row["job_title"] or "",
        "signer_organisation": request_row["organisation"] or "",
        "referee_email_public": is_public_email(request_row["referee_email"]),
    }

    return render_template(
        "index.html",
        csrf_token=generate_csrf_token(),
        form_data=prefilled_data,
        errors=[],
        token=token,
        employment_types=sorted(EMPLOYMENT_TYPES),
    )


@app.route("/reference/<token>/started", methods=["POST"])
def reference_started(token):
    validate_public_csrf_header()

    with closing(get_connection()) as connection:
        with connection:
            request_row = connection.execute("""
                SELECT * FROM reference_requests
                WHERE token = ?
            """, (token,)).fetchone()

            if request_row is None:
                return "Invalid reference link.", 404
            if request_row["status"] == "completed":
                return "This reference has already been submitted.", 403

            existing = connection.execute("""
                SELECT id FROM reference_events
                WHERE request_id = ?
                  AND event_type = 'reference_started'
                LIMIT 1
            """, (request_row["id"],)).fetchone()

            if existing is None:
                record_reference_event(
                    request_row["id"],
                    "reference_started",
                    "Reference form started",
                    None,
                    connection=connection,
                )

    return ("", 204)


@app.route("/submit", methods=["GET", "POST"])
def submit():
    return "Public submissions are disabled. Use a secure reference link.", 403


@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "all").strip().lower()
    if status_filter not in {"all", "sent", "opened", "completed"}:
        status_filter = "all"

    with closing(get_connection()) as connection:
        org_where = ""
        org_params = []
        if g.current_user["role"] != "super_admin":
            org_where = " WHERE organisation_id = ?"
            org_params = [g.current_user["organisation_id"]]
        summary = {
            "total": connection.execute(f"SELECT COUNT(*) FROM reference_requests{org_where}", org_params).fetchone()[0],
            "sent": connection.execute(
                f"SELECT COUNT(*) FROM reference_requests WHERE status = ?{' AND organisation_id = ?' if org_params else ''}",
                ["sent"] + org_params,
            ).fetchone()[0],
            "opened": connection.execute(
                f"SELECT COUNT(*) FROM reference_requests WHERE status = ?{' AND organisation_id = ?' if org_params else ''}",
                ["opened"] + org_params,
            ).fetchone()[0],
            "completed": connection.execute(
                f"SELECT COUNT(*) FROM reference_requests WHERE status = ?{' AND organisation_id = ?' if org_params else ''}",
                ["completed"] + org_params,
            ).fetchone()[0],
            # TODO: Add real expiry logic when request expiry dates are introduced.
            "expired": 0,
            "verification_pending": 0,
        }
        if g.current_user["role"] == "super_admin":
            summary["verification_pending"] = connection.execute("""
                SELECT COUNT(*)
                FROM reference_verification_documents
                WHERE review_status = 'not_reviewed'
            """).fetchone()[0]
        else:
            summary["verification_pending"] = connection.execute("""
                SELECT COUNT(*)
                FROM reference_verification_documents vd
                JOIN reference_requests rr ON rr.id = vd.request_id
                WHERE vd.review_status = 'not_reviewed'
                  AND rr.organisation_id = ?
            """, (g.current_user["organisation_id"],)).fetchone()[0]

        where_clauses = []
        params = []
        if g.current_user["role"] != "super_admin":
            where_clauses.append("rr.organisation_id = ?")
            params.append(g.current_user["organisation_id"])
        if status_filter != "all":
            where_clauses.append("rr.status = ?")
            params.append(status_filter)
        if search:
            where_clauses.append("""
                (
                    rr.candidate_name LIKE ?
                    OR rr.referee_name LIKE ?
                    OR rr.organisation LIKE ?
                )
            """)
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        requests = connection.execute(f"""
            SELECT
                rr.*,
                rt.id AS reference_id,
                rt.reference_type,
                rt.submitted_at AS reference_submitted_at,
                u.first_name AS creator_first_name,
                u.last_name AS creator_last_name,
                u.email AS creator_email,
                vd.id AS verification_document_id,
                vd.review_status AS verification_status
            FROM reference_requests rr
            LEFT JOIN references_table rt ON rt.request_id = rr.id
            LEFT JOIN users u ON u.id = rr.created_by_user_id
            LEFT JOIN reference_verification_documents vd ON vd.request_id = rr.id
            {where_sql}
            ORDER BY COALESCE(rr.completed_at, rr.opened_at, rr.sent_at, rr.created_at) DESC
        """, params).fetchall()

    return render_template(
        "dashboard.html",
        summary=summary,
        requests=requests,
        search=search,
        status_filter=status_filter,
        csrf_token=generate_csrf_token(),
        current_user=g.current_user,
    )


@app.route("/reference-request/<int:request_id>/resend-email", methods=["POST"])
@login_required
def resend_reference_email(request_id):
    validate_csrf_token()
    request_row = get_request_for_current_user_or_404(request_id)

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
        # Zoho/basic SMTP success confirms server acceptance, not final inbox delivery.
        # TODO: Add webhook-based delivery tracking with a transactional email provider.
        record_reference_event(
            request_row["id"],
            "resend_email_sent",
            "Invitation email resent",
            f"Recipient: {mask_email(request_row['referee_email'])}",
        )
    except Exception as exc:
        email_sent = False
        record_reference_event(
            request_row["id"],
            "resend_email_failed",
            "Invitation email resend failed",
            safe_failure_category(exc),
        )

    return render_template(
        "request_created.html",
        request_id=request_row["id"],
        secure_link=secure_link,
        email_sent=email_sent,
    )


@app.route("/verification-document/<int:document_id>/download")
@login_required
def download_verification_document(document_id):
    document = get_verification_document_for_current_user_or_404(document_id)
    file_path = private_upload_root() / document["stored_filename"]
    if not file_path.exists():
        abort(404)
    content = file_path.read_bytes()
    record_reference_event(
        document["request_id"],
        "verification_document_downloaded",
        "Verification document downloaded",
        f"Document ID: {document_id}; Filename: {document['original_filename']}",
    )
    response = make_response(content)
    response.headers["Content-Type"] = document["mime_type"]
    response.headers["Content-Disposition"] = f'attachment; filename="{document["original_filename"]}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.route("/verification-document/<int:document_id>/review", methods=["POST"])
@login_required
def review_verification_document(document_id):
    validate_csrf_token()
    document = get_verification_document_for_current_user_or_404(document_id)
    action = request.form.get("action")
    if action not in {"accepted", "rejected"}:
        abort(400)
    notes = request.form.get("review_notes", "").strip()[:1000]
    with closing(get_connection()) as connection:
        with connection:
            connection.execute("""
                UPDATE reference_verification_documents
                SET review_status = ?,
                    reviewed_by_user_id = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    review_notes = ?
                WHERE id = ?
            """, (action, g.current_user["id"], notes, document_id))
            record_reference_event(
                document["request_id"],
                f"verification_document_{action}",
                f"Verification document {action}",
                f"Document ID: {document_id}",
                connection=connection,
            )
    return redirect(url_for("reference_timeline", request_id=document["request_id"]))


@app.route("/database-view")
@login_required
def database_view():
    search = request.args.get("search", "").strip()

    with closing(get_connection()) as connection:
        org_join = ""
        org_where = ""
        params = []
        if g.current_user["role"] != "super_admin":
            org_join = "JOIN reference_requests rr ON rr.id = rt.request_id"
            org_where = "rr.organisation_id = ?"
            params.append(g.current_user["organisation_id"])
        if search:
            where_parts = [org_where] if org_where else []
            where_parts.append("rt.candidate_name LIKE ?")
            params.append(f"%{search}%")
            rows = connection.execute("""
                SELECT rt.* FROM references_table rt
                {org_join}
                WHERE {where_sql}
                ORDER BY rt.submitted_at DESC
            """.format(org_join=org_join, where_sql=" AND ".join(where_parts)), params).fetchall()
        else:
            if org_where:
                rows = connection.execute("""
                    SELECT rt.* FROM references_table rt
                    JOIN reference_requests rr ON rr.id = rt.request_id
                    WHERE rr.organisation_id = ?
                    ORDER BY rt.submitted_at DESC
                """, (g.current_user["organisation_id"],)).fetchall()
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


@app.route("/super-admin")
@require_role("super_admin")
def super_admin_dashboard():
    with closing(get_connection()) as connection:
        stats = {
            "total_organisations": connection.execute("SELECT COUNT(*) FROM organisations").fetchone()[0],
            "active_organisations": connection.execute("SELECT COUNT(*) FROM organisations WHERE status = 'active'").fetchone()[0],
            "suspended_organisations": connection.execute("SELECT COUNT(*) FROM organisations WHERE status = 'suspended'").fetchone()[0],
            "total_recruiters": connection.execute("SELECT COUNT(*) FROM users WHERE role IN ('organisation_admin', 'recruiter')").fetchone()[0],
            "total_requests": connection.execute("SELECT COUNT(*) FROM reference_requests").fetchone()[0],
            "sent": connection.execute("SELECT COUNT(*) FROM reference_requests WHERE status = 'sent'").fetchone()[0],
            "opened": connection.execute("SELECT COUNT(*) FROM reference_requests WHERE status = 'opened'").fetchone()[0],
            "completed": connection.execute("SELECT COUNT(*) FROM reference_requests WHERE status = 'completed'").fetchone()[0],
            "failed_emails": connection.execute("""
                SELECT COUNT(*) FROM reference_events
                WHERE event_type IN ('invitation_email_failed', 'admin_notification_failed', 'resend_email_failed')
            """).fetchone()[0],
            "verification_pending": connection.execute("""
                SELECT COUNT(*) FROM reference_verification_documents
                WHERE review_status = 'not_reviewed'
            """).fetchone()[0],
        }
        organisations = connection.execute("""
            SELECT
                o.*,
                COUNT(DISTINCT u.id) AS recruiter_count,
                COUNT(DISTINCT rr.id) AS request_count,
                COUNT(DISTINCT rt.id) AS completed_count,
                MAX(COALESCE(rr.completed_at, rr.opened_at, rr.sent_at, rr.created_at)) AS last_activity
            FROM organisations o
            LEFT JOIN users u ON u.organisation_id = o.id
            LEFT JOIN reference_requests rr ON rr.organisation_id = o.id
            LEFT JOIN references_table rt ON rt.request_id = rr.id
            GROUP BY o.id
            ORDER BY o.created_at DESC
        """).fetchall()
    return render_template(
        "super_admin.html",
        stats=stats,
        organisations=organisations,
        csrf_token=generate_csrf_token(),
    )


@app.route("/super-admin/organisations/create", methods=["GET", "POST"])
@require_role("super_admin")
def create_organisation():
    errors = []
    if request.method == "POST":
        validate_csrf_token()
        name = request.form.get("name", "").strip()
        slug = slugify(request.form.get("slug", "") or name)
        primary_contact_email = request.form.get("primary_contact_email", "").strip().lower()
        if not name:
            errors.append("Organisation name is required.")
        if not errors:
            try:
                with closing(get_connection()) as connection:
                    with connection:
                        cursor = connection.execute("""
                            INSERT INTO organisations (
                                name, slug, status, primary_contact_name,
                                primary_contact_email, subscription_plan, created_at
                            )
                            VALUES (?, ?, 'active', ?, ?, ?, CURRENT_TIMESTAMP)
                        """, (
                            name,
                            slug,
                            request.form.get("primary_contact_name", "").strip(),
                            primary_contact_email,
                            request.form.get("subscription_plan", "trial").strip() or "trial",
                        ))
                        organisation_id = cursor.lastrowid
                        record_platform_event(
                            "organisation_created",
                            "Organisation created",
                            f"Organisation: {name}",
                            organisation_id=organisation_id,
                            connection=connection,
                        )
                return redirect(url_for("super_admin_dashboard"))
            except sqlite3.IntegrityError:
                errors.append("Organisation slug must be unique.")
    return render_template("organisation_form.html", errors=errors, csrf_token=generate_csrf_token())


@app.route("/super-admin/organisations/<int:organisation_id>/<action>", methods=["POST"])
@require_role("super_admin")
def update_organisation_status(organisation_id, action):
    validate_csrf_token()
    if action not in {"suspend", "reactivate"}:
        abort(404)
    new_status = "suspended" if action == "suspend" else "active"
    event_type = "organisation_suspended" if action == "suspend" else "organisation_reactivated"
    label = "Organisation suspended" if action == "suspend" else "Organisation reactivated"
    with closing(get_connection()) as connection:
        with connection:
            organisation = connection.execute("SELECT * FROM organisations WHERE id = ?", (organisation_id,)).fetchone()
            if organisation is None:
                abort(404)
            connection.execute("""
                UPDATE organisations
                SET status = ?,
                    suspended_at = CASE WHEN ? = 'suspended' THEN CURRENT_TIMESTAMP ELSE NULL END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (new_status, new_status, organisation_id))
            record_platform_event(event_type, label, f"Organisation: {organisation['name']}", organisation_id=organisation_id, connection=connection)
    return redirect(url_for("super_admin_dashboard"))


@app.route("/super-admin/organisations/<int:organisation_id>/users/create", methods=["GET", "POST"])
@require_role("super_admin")
def super_admin_create_user(organisation_id):
    errors = []
    with closing(get_connection()) as connection:
        organisation = connection.execute("SELECT * FROM organisations WHERE id = ?", (organisation_id,)).fetchone()
    if organisation is None:
        abort(404)
    if request.method == "POST":
        validate_csrf_token()
        role = request.form.get("role", "organisation_admin")
        if role not in {"organisation_admin", "recruiter"}:
            errors.append("Super Admin can create organisation admins or recruiters here.")
        password = request.form.get("password", "")
        if len(password) < 8:
            errors.append("Temporary password must be at least 8 characters.")
        if not errors:
            try:
                with closing(get_connection()) as connection:
                    with connection:
                        user_id = create_user_account(
                            request.form.get("email", ""),
                            password,
                            role,
                            organisation_id=organisation_id,
                            first_name=request.form.get("first_name", ""),
                            last_name=request.form.get("last_name", ""),
                            connection=connection,
                        )
                        record_platform_event(
                            "recruiter_created",
                            "Recruiter created",
                            f"User ID: {user_id}; Role: {role}",
                            organisation_id=organisation_id,
                            connection=connection,
                        )
                return redirect(url_for("super_admin_dashboard"))
            except sqlite3.IntegrityError:
                errors.append("Email address must be unique.")
    return render_template(
        "user_form.html",
        errors=errors,
        organisation=organisation,
        allowed_roles=["organisation_admin", "recruiter"],
        csrf_token=generate_csrf_token(),
    )


@app.route("/organisation/users/create", methods=["GET", "POST"])
@require_role("organisation_admin")
def organisation_create_recruiter():
    errors = []
    if request.method == "POST":
        validate_csrf_token()
        password = request.form.get("password", "")
        if len(password) < 8:
            errors.append("Temporary password must be at least 8 characters.")
        if not errors:
            try:
                with closing(get_connection()) as connection:
                    with connection:
                        user_id = create_user_account(
                            request.form.get("email", ""),
                            password,
                            "recruiter",
                            organisation_id=g.current_user["organisation_id"],
                            first_name=request.form.get("first_name", ""),
                            last_name=request.form.get("last_name", ""),
                            connection=connection,
                        )
                        record_platform_event(
                            "recruiter_created",
                            "Recruiter created",
                            f"User ID: {user_id}; Role: recruiter",
                            organisation_id=g.current_user["organisation_id"],
                            connection=connection,
                        )
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                errors.append("Email address must be unique.")
    return render_template(
        "user_form.html",
        errors=errors,
        organisation=g.current_user,
        allowed_roles=["recruiter"],
        csrf_token=generate_csrf_token(),
    )


@app.route("/reference-request/<int:request_id>/timeline")
@login_required
def reference_timeline(request_id):
    scoped_request = get_request_for_current_user_or_404(request_id)
    with closing(get_connection()) as connection:
        request_row = connection.execute("""
            SELECT
                rr.id,
                rr.candidate_name,
                rr.referee_name,
                rr.referee_email,
                rr.organisation,
                rr.job_title,
                rr.status,
                rt.id AS reference_id
            FROM reference_requests rr
            LEFT JOIN references_table rt ON rt.request_id = rr.id
            WHERE rr.id = ?
        """, (request_id,)).fetchone()

        if request_row is None:
            abort(404)

        events = connection.execute("""
            SELECT event_type, event_label, event_details, created_at
            FROM reference_events
            WHERE request_id = ?
            ORDER BY created_at ASC, id ASC
        """, (request_id,)).fetchall()

    return render_template(
        "reference_timeline.html",
        request_row=request_row,
        events=events,
        csrf_token=generate_csrf_token(),
    )


@app.route("/reference/<int:reference_id>/view")
@login_required
def reference_detail(reference_id):
    row = get_reference_for_current_user_or_404(reference_id)
    if g.current_user["role"] == "super_admin":
        record_reference_event(
            row["request_id"],
            "super_admin_sensitive_record_accessed",
            "Super Admin sensitive record accessed",
            f"Reference ID: {reference_id}",
        )
    with closing(get_connection()) as connection:
        verification_documents = connection.execute("""
            SELECT vd.*, u.email AS reviewed_by_email
            FROM reference_verification_documents vd
            LEFT JOIN users u ON u.id = vd.reviewed_by_user_id
            WHERE vd.request_id = ?
            ORDER BY vd.uploaded_at DESC
        """, (row["request_id"],)).fetchall()
        for document in verification_documents:
            record_reference_event(
                row["request_id"],
                "verification_document_viewed",
                "Verification document metadata viewed",
                f"Document ID: {document['id']}",
            )
    return render_template(
        "reference_detail.html",
        row=row,
        verification_documents=verification_documents,
        csrf_token=generate_csrf_token(),
    )


def get_completed_reference(reference_id):
    return get_reference_for_current_user_or_404(reference_id)


def clean_filename(value):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", value or "Reference").strip("_")
    return cleaned[:80] or "Reference"


def slugify(value):
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug or f"organisation-{secrets.token_hex(4)}"


def create_user_account(email, password, role, organisation_id=None, first_name="", last_name="", connection=None):
    if role not in ROLES:
        raise ValueError("Invalid role.")
    if role == "super_admin" and organisation_id is not None:
        raise ValueError("Super Admin accounts must not belong to an organisation.")
    if role != "super_admin" and organisation_id is None:
        raise ValueError("Organisation users must belong to an organisation.")
    owns_connection = connection is None
    target_connection = connection or get_connection()
    try:
        cursor = target_connection.execute("""
            INSERT INTO users (
                organisation_id, email, password_hash, first_name, last_name,
                role, status, created_at, password_changed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (
            organisation_id,
            email.strip().lower(),
            generate_password_hash(password),
            first_name.strip(),
            last_name.strip(),
            role,
        ))
        if owns_connection:
            target_connection.commit()
        return cursor.lastrowid
    finally:
        if owns_connection:
            target_connection.close()


def pdf_reference_type_title(reference_type):
    if reference_type == "employment_statement":
        return "Statement of Employment"
    return "Employment Reference"


class NumberedCanvas:
    def __init__(self, *args, footer_data=None, **kwargs):
        from reportlab.pdfgen.canvas import Canvas

        self._canvas = Canvas(*args, **kwargs)
        self.footer_data = footer_data or {}
        self._saved_page_states = []

    def __getattr__(self, name):
        return getattr(self._canvas, name)

    def showPage(self):
        self._saved_page_states.append(dict(self._canvas.__dict__))
        self._canvas._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self._canvas.__dict__.update(state)
            self.draw_footer(page_count)
            self._canvas.showPage()
        self._canvas.save()

    def draw_footer(self, page_count):
        canvas = self._canvas
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#DCE4EC"))
        canvas.line(18 * mm, 22 * mm, 192 * mm, 22 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#334155"))
        canvas.drawString(18 * mm, 17 * mm, "Generated by ReferenceBridge")
        canvas.drawString(18 * mm, 13.5 * mm, f"Generated: {self.footer_data.get('generated_at')}")
        canvas.drawString(18 * mm, 10 * mm, f"Document reference: {self.footer_data.get('document_reference')}")
        canvas.drawRightString(192 * mm, 17 * mm, f"Page {canvas.getPageNumber()} of {page_count}")
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(
            78 * mm,
            13.5 * mm,
            "This document contains confidential employment reference information and should be handled securely.",
        )
        canvas.drawString(
            78 * mm,
            10 * mm,
            f"Document file hash: {self.footer_data.get('hash_short')}",
        )
        canvas.restoreState()


def pdf_table(rows, first_width=52 * mm, second_width=112 * mm):
    table = Table(rows, colWidths=[first_width, second_width], repeatRows=0)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef4f8")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#082344")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def generate_reference_pdf(row):
    buffer = BytesIO()
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    document_reference = f"RB-{row['request_id'] or row['audit_request_id']}-{row['id']}"
    hash_source = f"{document_reference}|{row['candidate_name']}|{row['completed_at'] or row['submitted_at']}"
    document_hash = hashlib.sha256(hash_source.encode("utf-8")).hexdigest()
    hash_short = f"{document_hash[:16]}...{document_hash[-16:]}"
    # A SHA-256 hash can detect file changes, but it does not independently prove
    # signer identity or document authenticity. This PDF is not digitally signed.
    verification_supplied = "No"
    verification_status = "Not required"
    reviewed_by = None
    reviewed_at = None
    if row["request_id"]:
        with closing(get_connection()) as connection:
            verification = connection.execute("""
                SELECT vd.*, u.email AS reviewed_by_email
                FROM reference_verification_documents vd
                LEFT JOIN users u ON u.id = vd.reviewed_by_user_id
                WHERE vd.request_id = ?
                ORDER BY vd.uploaded_at DESC
                LIMIT 1
            """, (row["request_id"],)).fetchone()
        if verification:
            verification_supplied = "Yes"
            verification_status = verification["review_status"].replace("_", " ").title()
            reviewed_by = verification["reviewed_by_email"]
            reviewed_at = verification["reviewed_at"]

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=28 * mm,
        title=f"ReferenceBridge {document_reference}",
        pageCompression=0,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="DocTitle", fontName="Helvetica-Bold", fontSize=18, textColor=colors.HexColor("#0B2E59"), alignment=2))
    styles.add(ParagraphStyle(name="Section", fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor("#0B2E59"), spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="BodyWrap", fontSize=9, leading=12, splitLongWords=True))
    styles.add(ParagraphStyle(name="Declaration", fontSize=10, leading=14, textColor=colors.HexColor("#334155"), backColor=colors.HexColor("#F6F8FB"), borderColor=colors.HexColor("#DCE4EC"), borderWidth=0.5, borderPadding=8, spaceAfter=8))

    def cell(value):
        return Paragraph(str(value or "Not recorded"), styles["BodyWrap"])

    logo_path = Path(__file__).with_name("static") / "images" / "referencebridge-logo-horizontal.png"
    logo_cell = Image(str(logo_path), width=180, height=44, kind="proportional") if logo_path.exists() else cell("ReferenceBridge\nBridging Trust in Recruitment")
    header = Table([[logo_cell, Paragraph(pdf_reference_type_title(row["reference_type"]), styles["DocTitle"])]], colWidths=[90 * mm, 74 * mm])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor("#DCE4EC")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    elements = [header, Spacer(1, 8 * mm)]
    elements.extend([
        Paragraph("Document Information", styles["Section"]),
        pdf_table([
            ["Document reference", cell(document_reference)],
            ["Generated", cell(generated_at)],
            ["Request ID", cell(row["request_id"] or row["audit_request_id"])],
            ["Reference type", cell(reference_type_label(row["reference_type"]))],
            ["Document file hash", cell(hash_short)],
        ]),
        Paragraph("Candidate Information", styles["Section"]),
        pdf_table([
            ["Candidate name", cell(row["candidate_name"])],
            ["Job title", cell(row["job_title"])],
        ]),
        Paragraph("Referee Information", styles["Section"]),
        pdf_table([
            ["Referee name", cell(row["referee_name"])],
            ["Referee email", cell(row["referee_email"])],
            ["Email type", cell("Public email provider" if is_public_email(row["referee_email"]) else "Organisation domain")],
            ["Organisation", cell(row["organisation"])],
        ]),
        Paragraph("Employment Information", styles["Section"]),
    ])

    if row["reference_type"] == "employment_statement":
        elements.extend([
            pdf_table([
            ["Employment start date", cell(row["start_date"])],
            ["Employment end date", cell(row["end_date"])],
            ["Position/job title", cell(row["job_title"])],
            ["Employment type", cell(row["employment_type"])],
            ]),
            Paragraph("Comments", styles["Section"]),
            pdf_table([
            ["Statement text", cell(row["statement_text"])],
            ], first_width=40 * mm, second_width=124 * mm),
        ])
    else:
        elements.extend([
            pdf_table([
            ["Relationship", cell(row["relationship"])],
            ["Employment dates", cell(f"{row['start_date']} to {row['end_date']}")],
            ]),
            Paragraph("Assessment", styles["Section"]),
            pdf_table([
            ["Clinical competence", cell(row["clinical_competence"])],
            ["Communication skills", cell(row["communication_skills"])],
            ["Professional conduct", cell(row["professional_conduct"])],
            ["Rehire response", cell(row["rehire"])],
            ]),
            Paragraph("Comments", styles["Section"]),
            pdf_table([
            ["Reference comments", cell(row["reference_text"])],
            ], first_width=40 * mm, second_width=124 * mm),
        ])

    elements.extend([
        Paragraph("Referee Declaration and Signature", styles["Section"]),
        Paragraph("I confirm that the information supplied in this reference is accurate to the best of my knowledge and that I am authorised to provide this reference.", styles["Declaration"]),
        pdf_table([
            ["Referee name", cell(row["signer_name"] or row["referee_name"])],
            ["Job title", cell(row["signer_job_title"] or row["job_title"])],
            ["Organisation", cell(row["signer_organisation"] or row["organisation"])],
            ["Electronic signature", cell(row["electronic_signature"] or row["signature"])],
            ["Date signed", cell(row["signed_at"] or row["completed_at"] or row["submitted_at"])],
            ["Declaration confirmed", cell("Yes" if row["declaration_confirmed"] else "No")],
            ["Signature method", cell("Electronically signed through ReferenceBridge.")],
        ]),
        Paragraph("Verification Information", styles["Section"]),
        pdf_table([
            ["Referee email type", cell("Public email provider" if is_public_email(row["referee_email"]) else "Organisation domain")],
            ["Supporting verification document supplied", cell(verification_supplied)],
            ["Review status", cell(verification_status)],
            *([["Reviewed by", cell(reviewed_by)]] if reviewed_by else []),
            *([["Reviewed at", cell(reviewed_at)]] if reviewed_at else []),
        ]),
        Paragraph("Document Footer", styles["Section"]),
        pdf_table([
            ["Generated by", cell("ReferenceBridge")],
            ["Generated", cell(generated_at)],
            ["Document reference", cell(document_reference)],
            ["Confidentiality notice", cell("This document contains confidential employment reference information and should be handled securely.")],
        ]),
    ])
    doc.build(
        elements,
        canvasmaker=lambda *args, **kwargs: NumberedCanvas(
            *args,
            footer_data={
                "generated_at": generated_at,
                "document_reference": document_reference,
                "hash_short": hash_short,
            },
            **kwargs,
        ),
    )
    return buffer.getvalue()


@app.route("/reference/<int:reference_id>/pdf")
@login_required
def reference_pdf(reference_id):
    row = get_completed_reference(reference_id)
    if row is None:
        abort(404)
    if row["status"] != "completed":
        return "Reference is not completed.", 409

    pdf_bytes = generate_reference_pdf(row)
    if row["request_id"]:
        record_reference_event(
            row["request_id"],
            "reference_downloaded",
            "Completed reference PDF downloaded",
            f"Candidate: {row['candidate_name']}; Request ID: {row['request_id']}",
        )
        record_reference_event(
            row["request_id"],
            "pdf_downloaded",
            "Completed reference PDF downloaded",
            f"Candidate: {row['candidate_name']}; Request ID: {row['request_id']}",
        )

    completed_date = str(row["request_completed_at"] or row["completed_at"] or row["submitted_at"] or "reference")[:10]
    filename = f"ReferenceBridge_{clean_filename(row['candidate_name'])}_{clean_filename(completed_date)}.pdf"
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/references/<int:reference_id>/export-pdf")
@login_required
def export_reference_pdf(reference_id):
    return redirect(url_for("reference_pdf", reference_id=reference_id))


if __name__ == "__main__":
    init_database()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
