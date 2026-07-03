import os
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
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
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    wrapped_view.__name__ = view.__name__
    return wrapped_view


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


@app.route("/submit", methods=["POST"])
def submit():
    validate_csrf_token()
    form_data = get_reference_form_data()
    errors = validate_reference(form_data)

    if errors:
        return render_template(
            "index.html",
            csrf_token=generate_csrf_token(),
            form_data=form_data,
            errors=errors,
        ), 400

    with closing(get_connection()) as connection:
        with connection:
            connection.execute("""
                INSERT INTO references_table (
                    candidate_name, referee_name, referee_email, organisation,
                    job_title, relationship, start_date, end_date, rehire,
                    clinical_competence, communication_skills, professional_conduct,
                    reference_text, signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
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
            ))

    return render_template("submitted.html")


@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "")

    with closing(get_connection()) as connection:
        total_references = connection.execute(
            "SELECT COUNT(*) FROM references_table"
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

    return render_template(
        "dashboard.html",
        total_references=total_references,
        rehire_yes=rehire_yes,
        rehire_no=rehire_no,
        rehire_reservations=rehire_reservations,
        rows=rows,
        search=search
    )


@app.route("/database-view")
@login_required
def database_view():
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM references_table ORDER BY submitted_at DESC"
        ).fetchall()

    return render_template("database_view.html", rows=rows)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
