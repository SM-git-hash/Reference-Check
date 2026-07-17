import sqlite3
import re
from io import BytesIO
from contextlib import closing

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app, init_database


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "references.db"

    monkeypatch.setenv("ADMIN_PASSWORD", "test-password")
    app.config.update(
        DATABASE=str(database_path),
        SECRET_KEY="test-secret",
        TESTING=True,
    )
    init_database()

    with app.test_client() as test_client:
        yield test_client


def csrf_token(response):
    match = re.search(
        rb'name="csrf_token" value="([^"]+)"',
        response.data,
    )
    assert match
    return match.group(1).decode()


def valid_reference(token):
    return {
        "csrf_token": token,
        "reference_type": "full_reference",
        "candidate_name": "Alex Candidate",
        "referee_name": "Robin Referee",
        "referee_email": "robin@example.com",
        "organisation": "Reference Hospital",
        "job_title": "Nurse",
        "relationship": "Manager",
        "start_date": "2024-01-01",
        "end_date": "2025-01-01",
        "rehire": "Yes",
        "clinical_competence": "Excellent",
        "communication_skills": "Good",
        "professional_conduct": "Satisfactory",
        "reference_text": "Reliable and professional.",
        "signature": "Robin Referee",
        "signer_name": "Robin Referee",
        "signer_job_title": "Ward Manager",
        "signer_organisation": "Reference Hospital",
        "electronic_signature": "Robin Referee",
        "declaration_confirmed": "1",
    }


def valid_statement(token):
    return {
        "csrf_token": token,
        "reference_type": "employment_statement",
        "candidate_name": "Alex Candidate",
        "referee_name": "Robin Referee",
        "referee_email": "robin@example.com",
        "organisation": "Reference Hospital",
        "job_title": "Nurse",
        "start_date": "2024-01-01",
        "end_date": "2025-01-01",
        "employment_type": "Full-time",
        "statement_text": "Alex Candidate was employed as a Nurse.",
        "accuracy_confirmed": "1",
        "signature": "Robin Referee",
        "signer_name": "Robin Referee",
        "signer_job_title": "Ward Manager",
        "signer_organisation": "Reference Hospital",
        "electronic_signature": "Robin Referee",
        "declaration_confirmed": "1",
    }


def create_reference_request(token="secure-token", status="sent", organisation_id=None, created_by_user_id=None, referee_email="robin@example.com"):
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
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
                    sent_at,
                    organisation_id,
                    created_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
            """, (
                "Alex Candidate",
                "Robin Referee",
                referee_email,
                "Reference Hospital",
                "Nurse",
                token,
                status,
                organisation_id,
                created_by_user_id,
            ))
    return cursor.lastrowid, token


def event_rows(request_id=None):
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        if request_id is None:
            return connection.execute(
                "SELECT event_type, event_label, event_details FROM reference_events ORDER BY created_at, id"
            ).fetchall()
        return connection.execute(
            "SELECT event_type, event_label, event_details FROM reference_events WHERE request_id = ? ORDER BY created_at, id",
            (request_id,),
        ).fetchall()


def latest_reference_id():
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        return connection.execute("SELECT id FROM references_table ORDER BY id DESC LIMIT 1").fetchone()[0]


def create_org(name="Test Org", slug="test-org", status="active"):
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        with connection:
            cursor = connection.execute("""
                INSERT INTO organisations (name, slug, status, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (name, slug, status))
    return cursor.lastrowid


def create_user(email, password, role, organisation_id=None, status="active"):
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        with connection:
            cursor = connection.execute("""
                INSERT INTO users (
                    organisation_id, email, password_hash, role, status, created_at
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (organisation_id, email, generate_password_hash(password), role, status))
    return cursor.lastrowid


def login_as(client, email, password="password123"):
    response = client.get("/login")
    token = csrf_token(response)
    return client.post(
        "/login",
        data={"csrf_token": token, "email": email, "password": password},
        follow_redirects=True,
    )


def login(client):
    response = client.get("/login")
    token = csrf_token(response)
    return client.post(
        "/login",
        data={"csrf_token": token, "password": "test-password"},
        follow_redirects=True,
    )


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_database_view_requires_login(client):
    response = client.get("/database-view")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_create_request_requires_login(client):
    response = client.get("/create-request")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_root_redirects_to_login_when_logged_out(client):
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_root_redirects_to_dashboard_when_logged_in(client):
    login(client)

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_correct_password_logs_in(client):
    response = login(client)

    assert response.status_code == 200
    with client.session_transaction() as session_data:
        assert session_data["logged_in"] is True


def test_incorrect_password_fails(client):
    response = client.get("/login")
    csrf = csrf_token(response)

    response = client.post(
        "/login",
        data={"csrf_token": csrf, "password": "wrong-password"},
    )

    assert response.status_code == 200
    assert b"Invalid password." in response.data
    with client.session_transaction() as session_data:
        assert session_data.get("logged_in") is not True


def test_missing_admin_password_uses_local_changeme_fallback(client, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    response = client.get("/login")
    csrf = csrf_token(response)

    response = client.post(
        "/login",
        data={"csrf_token": csrf, "password": "changeme"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_logout_clears_session_and_dashboard_is_inaccessible(client):
    response = login(client)
    csrf = csrf_token(response)

    response = client.post("/logout", data={"csrf_token": csrf})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    with client.session_transaction() as session_data:
        assert "logged_in" not in session_data

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_external_next_url_is_rejected(client):
    response = client.get("/login?next=https://evil.example")
    csrf = csrf_token(response)

    response = client.post(
        "/login?next=https://evil.example",
        data={"csrf_token": csrf, "password": "test-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_internal_next_url_is_allowed(client):
    response = client.get("/login?next=/create-request")
    csrf = csrf_token(response)

    response = client.post(
        "/login?next=/create-request",
        data={"csrf_token": csrf, "password": "test-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/create-request")


def test_public_submit_is_disabled(client):
    response = client.post("/submit", data={})

    assert response.status_code == 403
    assert b"Public submissions are disabled" in response.data


def test_new_request_starts_as_sent_and_records_sent_at(client, monkeypatch):
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)
    monkeypatch.setattr(app_module, "send_reference_request_receipt", lambda *args, **kwargs: None)
    login(client)
    response = client.get("/create-request")
    csrf = csrf_token(response)

    response = client.post("/create-request", data=create_request_form(csrf))

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT status, sent_at FROM reference_requests"
        ).fetchone()

    assert row[0] == "sent"
    assert row[1]


def test_admin_receipt_email_attempted_after_invitation_send(client, monkeypatch):
    receipt = {}
    monkeypatch.setattr(app_module, "admin_notification_email", lambda: "admin@example.com")
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)

    def fake_receipt(*args, **kwargs):
        receipt["called"] = True
        receipt["invitation_sent"] = kwargs["invitation_sent"]

    monkeypatch.setattr(app_module, "send_reference_request_receipt", fake_receipt)
    login(client)
    response = client.get("/create-request")
    csrf = csrf_token(response)

    client.post("/create-request", data=create_request_form(csrf))

    assert receipt == {"called": True, "invitation_sent": True}


def test_first_get_changes_sent_to_opened_and_records_opened_once(client):
    _, request_token = create_reference_request()

    first = client.get(f"/reference/{request_token}")

    assert first.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT status, opened_at FROM reference_requests WHERE token = ?",
            (request_token,),
        ).fetchone()
    assert row[0] == "opened"
    first_opened_at = row[1]
    assert first_opened_at

    second = client.get(f"/reference/{request_token}")

    assert second.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        opened_at = connection.execute(
            "SELECT opened_at FROM reference_requests WHERE token = ?",
            (request_token,),
        ).fetchone()[0]

    assert opened_at == first_opened_at


def test_invalid_token_returns_404(client):
    response = client.get("/reference/not-a-real-token")

    assert response.status_code == 404


def test_reference_submission_persists_valid_form(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    response = client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    assert response.status_code == 200
    assert b"submitted successfully" in response.data

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM references_table").fetchone()[0]
        status = connection.execute(
            "SELECT status FROM reference_requests WHERE token = ?",
            (request_token,),
        ).fetchone()[0]

    assert count == 1
    assert status == "completed"

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT reference_type, completed_at FROM references_table"
        ).fetchone()
        request_completed_at = connection.execute(
            "SELECT completed_at FROM reference_requests WHERE token = ?",
            (request_token,),
        ).fetchone()[0]

    assert row[0] == "full_reference"
    assert row[1]
    assert request_completed_at


def test_reference_submission_rejects_invalid_rating(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_reference(csrf)
    data["clinical_competence"] = "Magic"

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 400
    assert b"Clinical Competence must be a valid rating." in response.data


def test_full_reference_requires_full_fields(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_reference(csrf)
    data["clinical_competence"] = ""

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 400
    assert b"Clinical Competence is required." in response.data


def test_statement_only_does_not_require_rating_fields(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    response = client.post(f"/reference/{request_token}", data=valid_statement(csrf))

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT reference_type, clinical_competence, employment_type, accuracy_confirmed FROM references_table"
        ).fetchone()

    assert row[0] == "employment_statement"
    assert row[1] == ""
    assert row[2] == "Full-time"
    assert row[3] == 1


def test_statement_only_requires_statement_fields(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_statement(csrf)
    data.pop("accuracy_confirmed")
    data["statement_text"] = ""

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 400
    assert b"Statement Text is required." in response.data
    assert b"Accuracy Confirmed is required." in response.data


def test_statement_completion_changes_status_and_records_completed_at(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    response = client.post(f"/reference/{request_token}", data=valid_statement(csrf))

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT status, completed_at FROM reference_requests WHERE token = ?",
            (request_token,),
        ).fetchone()

    assert row[0] == "completed"
    assert row[1]


def test_admin_completion_email_attempted_after_commit(client, monkeypatch):
    completion = {}
    monkeypatch.setattr(app_module, "admin_notification_email", lambda: "admin@example.com")

    def fake_completion(*args, **kwargs):
        completion["called"] = True

    monkeypatch.setattr(app_module, "send_reference_completed_notification", fake_completion)
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    assert completion["called"] is True


def test_admin_completion_email_failure_does_not_roll_back(client, monkeypatch):
    monkeypatch.setattr(app_module, "admin_notification_email", lambda: "admin@example.com")

    def fake_completion(*args, **kwargs):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr(app_module, "send_reference_completed_notification", fake_completion)
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    response = client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM references_table").fetchone()[0]
    assert count == 1


def test_completed_token_cannot_be_reused(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = client.get(f"/reference/{request_token}")

    assert response.status_code == 403
    assert b"already been submitted" in response.data


def test_readonly_fields_cannot_be_tampered_with(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_reference(csrf)
    data["candidate_name"] = "Tampered Candidate"
    data["referee_email"] = "attacker@example.com"

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        row = connection.execute(
            "SELECT candidate_name, referee_email FROM references_table"
        ).fetchone()

    assert row[0] == "Alex Candidate"
    assert row[1] == "robin@example.com"


def test_dashboard_displays_records_after_login(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = login(client)

    assert response.status_code == 200
    assert b"Alex Candidate" in response.data
    assert b"Total Requests" in response.data
    assert b"Completed" in response.data


def create_request_form(csrf):
    return {
        "csrf_token": csrf,
        "candidate_name": "Casey Candidate",
        "referee_name": "Morgan Manager",
        "referee_email": "morgan@example.com",
        "organisation": "Bridge Care",
        "job_title": "Care Assistant",
    }


def test_create_request_sends_email_after_saving(client, monkeypatch):
    sent = {}

    def fake_send(referee_name, referee_email, candidate_name, secure_link):
        sent["referee_name"] = referee_name
        sent["referee_email"] = referee_email
        sent["candidate_name"] = candidate_name
        sent["secure_link"] = secure_link

    monkeypatch.setattr(app_module, "send_reference_invitation", fake_send)
    login(client)
    response = client.get("/create-request")
    csrf = csrf_token(response)

    response = client.post("/create-request", data=create_request_form(csrf))

    assert response.status_code == 200
    assert b"Reference request created and emailed successfully." in response.data
    assert sent["referee_email"] == "morgan@example.com"
    assert "reference/" in sent["secure_link"]

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM reference_requests").fetchone()[0]

    assert count == 1


def test_email_failure_does_not_roll_back_saved_request(client, monkeypatch):
    def fake_send(referee_name, referee_email, candidate_name, secure_link):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr(app_module, "send_reference_invitation", fake_send)
    login(client)
    response = client.get("/create-request")
    csrf = csrf_token(response)

    response = client.post("/create-request", data=create_request_form(csrf))

    assert response.status_code == 200
    assert b"Reference request created, but the email could not be sent." in response.data

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        rows = connection.execute("SELECT token FROM reference_requests").fetchall()

    assert len(rows) == 1
    assert rows[0][0]


def test_resend_requires_authentication(client):
    request_id, _ = create_reference_request()

    response = client.post(f"/reference-request/{request_id}/resend-email")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_resend_reuses_existing_token(client, monkeypatch):
    request_id, request_token = create_reference_request(token="existing-token")
    sent = {}

    def fake_send(referee_name, referee_email, candidate_name, secure_link):
        sent["secure_link"] = secure_link

    monkeypatch.setattr(app_module, "send_reference_invitation", fake_send)
    response = login(client)
    csrf = csrf_token(response)

    response = client.post(
        f"/reference-request/{request_id}/resend-email",
        data={"csrf_token": csrf},
    )

    assert response.status_code == 200
    assert request_token in sent["secure_link"]

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM reference_requests").fetchone()[0]

    assert count == 1


def test_completed_requests_cannot_be_resent(client, monkeypatch):
    request_id, _ = create_reference_request(status="completed")

    def fake_send(referee_name, referee_email, candidate_name, secure_link):
        raise AssertionError("completed requests should not send email")

    monkeypatch.setattr(app_module, "send_reference_invitation", fake_send)
    login(client)
    response = client.get("/create-request")
    csrf = csrf_token(response)

    response = client.post(
        f"/reference-request/{request_id}/resend-email",
        data={"csrf_token": csrf},
    )

    assert response.status_code == 403
    assert b"cannot be resent" in response.data


def test_request_created_event_is_recorded(client, monkeypatch):
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)
    monkeypatch.setattr(app_module, "send_reference_request_receipt", lambda *args, **kwargs: None)
    login(client)
    csrf = csrf_token(client.get("/create-request"))

    client.post("/create-request", data=create_request_form(csrf))

    rows = event_rows()
    assert rows[0][0] == "request_created"
    assert "example.com" in rows[0][2]


def test_invitation_email_sent_event_is_recorded_after_success(client, monkeypatch):
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)
    monkeypatch.setattr(app_module, "send_reference_request_receipt", lambda *args, **kwargs: None)
    login(client)
    csrf = csrf_token(client.get("/create-request"))

    client.post("/create-request", data=create_request_form(csrf))

    assert "invitation_email_sent" in [row[0] for row in event_rows()]


def test_invitation_email_failed_event_is_recorded_on_failure(client, monkeypatch):
    def fail(*args):
        raise RuntimeError("smtp unavailable with token=secret-token")

    monkeypatch.setattr(app_module, "send_reference_invitation", fail)
    monkeypatch.setattr(app_module, "send_reference_request_receipt", lambda *args, **kwargs: None)
    login(client)
    csrf = csrf_token(client.get("/create-request"))

    client.post("/create-request", data=create_request_form(csrf))

    rows = event_rows()
    failed = [row for row in rows if row[0] == "invitation_email_failed"][0]
    assert failed[2] == "Email send error"
    assert "secret-token" not in failed[2]


def test_first_token_get_records_link_opened_once(client):
    request_id, request_token = create_reference_request()

    client.get(f"/reference/{request_token}")
    client.get(f"/reference/{request_token}")

    rows = event_rows(request_id)
    assert [row[0] for row in rows].count("link_opened") == 1


def test_reference_started_endpoint_records_once(client):
    request_id, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)

    first = client.post(f"/reference/{request_token}/started", headers={"X-CSRFToken": csrf})
    second = client.post(f"/reference/{request_token}/started", headers={"X-CSRFToken": csrf})

    assert first.status_code == 204
    assert second.status_code == 204
    assert [row[0] for row in event_rows(request_id)].count("reference_started") == 1


def test_completion_and_admin_success_events_are_recorded(client, monkeypatch):
    monkeypatch.setattr(app_module, "admin_notification_email", lambda: "admin@example.com")
    monkeypatch.setattr(app_module, "send_reference_completed_notification", lambda *args: None)
    request_id, request_token = create_reference_request()
    csrf = csrf_token(client.get(f"/reference/{request_token}"))

    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    event_types = [row[0] for row in event_rows(request_id)]
    assert "reference_completed" in event_types
    assert "admin_notification_sent" in event_types


def test_admin_failure_event_is_recorded(client, monkeypatch):
    monkeypatch.setattr(app_module, "admin_notification_email", lambda: "admin@example.com")

    def fail(*args):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr(app_module, "send_reference_completed_notification", fail)
    request_id, request_token = create_reference_request()
    csrf = csrf_token(client.get(f"/reference/{request_token}"))

    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    assert "admin_notification_failed" in [row[0] for row in event_rows(request_id)]


def test_resend_success_and_failure_events(client, monkeypatch):
    request_id, _ = create_reference_request()
    login_response = login(client)
    csrf = csrf_token(login_response)
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)

    client.post(f"/reference-request/{request_id}/resend-email", data={"csrf_token": csrf})

    def fail(*args):
        raise RuntimeError("smtp unavailable")

    response = client.get("/dashboard")
    csrf = csrf_token(response)
    monkeypatch.setattr(app_module, "send_reference_invitation", fail)
    client.post(f"/reference-request/{request_id}/resend-email", data={"csrf_token": csrf})

    event_types = [row[0] for row in event_rows(request_id)]
    assert "resend_email_sent" in event_types
    assert "resend_email_failed" in event_types


def test_invalid_and_completed_tokens_do_not_create_extra_events(client):
    response = client.get("/reference/not-real")
    assert response.status_code == 404
    assert event_rows() == []

    request_id, request_token = create_reference_request()
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))
    before = len(event_rows(request_id))
    response = client.get(f"/reference/{request_token}")

    assert response.status_code == 403
    assert len(event_rows(request_id)) == before


def test_dashboard_summary_filters_search_and_pdf_actions(client):
    sent_id, _ = create_reference_request(token="sent-token", status="sent")
    opened_id, _ = create_reference_request(token="opened-token", status="opened")
    completed_id, completed_token = create_reference_request(token="completed-token")
    csrf = csrf_token(client.get(f"/reference/{completed_token}"))
    client.post(f"/reference/{completed_token}", data=valid_statement(csrf))
    login(client)

    response = client.get("/dashboard")
    assert b"Total Requests" in response.data
    assert b"Download PDF" in response.data

    response = client.get("/dashboard?status=completed")
    assert response.data.count(b"Download PDF") == 1
    assert b"Resend Email" not in response.data

    response = client.get("/dashboard?search=Reference+Hospital")
    assert response.status_code == 200
    assert b"Alex Candidate" in response.data

    response = client.get("/dashboard?status=sent")
    assert b"Download PDF" not in response.data
    assert b"Resend Email" in response.data
    assert sent_id and opened_id and completed_id


def test_timeline_requires_login_and_orders_events(client):
    request_id, _ = create_reference_request()
    app_module.record_reference_event(request_id, "request_created", "Request created")
    app_module.record_reference_event(request_id, "invitation_email_sent", "Invitation email accepted by mail server")

    response = client.get(f"/reference-request/{request_id}/timeline")
    assert response.status_code == 302

    login(client)
    response = client.get(f"/reference-request/{request_id}/timeline")
    assert response.status_code == 200
    assert response.data.index(b"Request created") < response.data.index(b"Invitation email accepted")


def test_pdf_route_auth_missing_incomplete_and_download_event(client):
    request_id, request_token = create_reference_request()
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))
    reference_id = latest_reference_id()

    response = client.get(f"/reference/{reference_id}/pdf")
    assert response.status_code == 302

    login(client)
    response = client.get("/reference/99999/pdf")
    assert response.status_code == 404

    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        with connection:
            cursor = connection.execute("""
                INSERT INTO references_table (
                    request_id, candidate_name, referee_name, referee_email, organisation, job_title,
                    relationship, start_date, end_date, rehire, clinical_competence,
                    communication_skills, professional_conduct, reference_text, signature, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, "Draft Candidate", "Robin Referee", "robin@example.com",
                "Reference Hospital", "Nurse", "Manager", "2024-01-01", "2025-01-01",
                "Yes", "Excellent", "Good", "Satisfactory", "Draft", "Robin", "draft",
            ))
            draft_id = cursor.lastrowid

    response = client.get(f"/reference/{draft_id}/pdf")
    assert response.status_code == 409

    response = client.get(f"/reference/{reference_id}/pdf")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert "ReferenceBridge_Alex_Candidate_" in response.headers["Content-Disposition"]
    assert b"secure-token" not in response.data
    assert b"Alex Candidate" in response.data
    assert b"Full Reference" in response.data
    assert "reference_downloaded" in [row[0] for row in event_rows(request_id)]


def test_statement_pdf_returns_pdf_with_correct_type(client):
    _, request_token = create_reference_request(token="statement-token")
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    client.post(f"/reference/{request_token}", data=valid_statement(csrf))
    reference_id = latest_reference_id()
    login(client)

    response = client.get(f"/reference/{reference_id}/pdf")

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert b"Statement of Employment" in response.data
    assert b"statement-token" not in response.data


def test_pdf_contains_signature_verification_and_no_todo(client):
    _, request_token = create_reference_request(token="pdf-token", referee_email="robin@gmail.com")
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))
    reference_id = latest_reference_id()
    login(client)

    response = client.get(f"/reference/{reference_id}/pdf")

    assert response.status_code == 200
    assert b"Referee Declaration and Signature" in response.data
    assert b"Electronically signed through ReferenceBridge" in response.data
    assert b"Verification Information" in response.data
    assert b"TODO" not in response.data
    assert b"Document file hash" in response.data


def test_valid_pdf_upload_is_private_and_download_audited(client):
    request_id, request_token = create_reference_request(token="upload-token", referee_email="robin@gmail.com")
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    data = valid_reference(csrf)
    data["verification_consent"] = "1"
    data["verification_document"] = (BytesIO(b"%PDF-1.4\nverification document"), "badge.pdf")

    response = client.post(
        f"/reference/{request_token}",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        document = connection.execute("""
            SELECT id, stored_filename, original_filename
            FROM reference_verification_documents
            WHERE request_id = ?
        """, (request_id,)).fetchone()

    assert document is not None
    assert document[1] != document[2]
    assert "static" not in document[1].lower()

    response = client.get(f"/verification-document/{document[0]}/download")
    assert response.status_code == 302
    login(client)
    response = client.get(f"/verification-document/{document[0]}/download")
    assert response.status_code == 200
    assert response.headers["Content-Disposition"].startswith("attachment")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "verification_document_downloaded" in [row[0] for row in event_rows(request_id)]


def test_valid_jpg_and_png_uploads_are_accepted(client):
    for extension, content in [
        ("jpg", b"\xff\xd8\xff\xe0photo"),
        ("png", b"\x89PNG\r\n\x1a\nimage"),
    ]:
        request_id, request_token = create_reference_request(token=f"upload-{extension}", referee_email=f"robin-{extension}@gmail.com")
        csrf = csrf_token(client.get(f"/reference/{request_token}"))
        data = valid_statement(csrf)
        data["verification_consent"] = "1"
        data["verification_document"] = (BytesIO(content), f"badge.{extension}")

        response = client.post(
            f"/reference/{request_token}",
            data=data,
            content_type="multipart/form-data",
        )

        assert response.status_code == 200
        with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM reference_verification_documents WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
        assert count == 1


def test_invalid_uploads_are_rejected(client):
    cases = [
        ((BytesIO(b"%PDF-1.4"), "badge.svg"), b"PDF, JPG, JPEG or PNG"),
        ((BytesIO(b"MZ executable"), "badge.pdf"), b"type is not allowed"),
        ((BytesIO(b"<html></html>"), "../badge.png"), b"type is not allowed"),
        ((BytesIO(b"a" * (5 * 1024 * 1024 + 1)), "badge.pdf"), b"5 MB or smaller"),
    ]
    for index, (file_tuple, expected) in enumerate(cases):
        _, request_token = create_reference_request(token=f"bad-upload-{index}", referee_email=f"bad{index}@gmail.com")
        csrf = csrf_token(client.get(f"/reference/{request_token}"))
        data = valid_reference(csrf)
        data["verification_consent"] = "1"
        data["verification_document"] = file_tuple

        response = client.post(
            f"/reference/{request_token}",
            data=data,
            content_type="multipart/form-data",
        )

        if index == 3:
            assert response.status_code in {400, 413}
        else:
            assert response.status_code == 400
            assert expected in response.data


def test_upload_requires_consent_when_file_supplied(client):
    _, request_token = create_reference_request(token="no-consent", referee_email="robin@gmail.com")
    csrf = csrf_token(client.get(f"/reference/{request_token}"))
    data = valid_reference(csrf)
    data["verification_document"] = (BytesIO(b"%PDF-1.4"), "badge.pdf")

    response = client.post(
        f"/reference/{request_token}",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Consent is required" in response.data


def test_organisation_user_login_and_suspended_org_blocked(client):
    org_id = create_org("Beaumont Hospital", "beaumont")
    create_user("admin@beaumont.test", "password123", "organisation_admin", org_id)

    response = login_as(client, "admin@beaumont.test")

    assert response.status_code == 200
    assert b"Beaumont Hospital" in response.data

    suspended_org = create_org("Suspended Org", "suspended-org", status="suspended")
    create_user("admin@suspended.test", "password123", "organisation_admin", suspended_org)
    response = login_as(client, "admin@suspended.test")
    assert b"Invalid password" in response.data or b"Account is not available" in response.data


def test_duplicate_email_and_org_slug_are_rejected(client):
    org_id = create_org("Duplicate Org", "duplicate-org")
    create_user("dupe@example.com", "password123", "recruiter", org_id)

    with pytest.raises(sqlite3.IntegrityError):
        create_user("dupe@example.com", "password123", "recruiter", org_id)
    with pytest.raises(sqlite3.IntegrityError):
        create_org("Duplicate Org Two", "duplicate-org")


def test_recruiter_data_isolation_for_dashboard_timeline_resend_and_pdf(client, monkeypatch):
    monkeypatch.setattr(app_module, "send_reference_invitation", lambda *args: None)
    org_a = create_org("Org A", "org-a")
    org_b = create_org("Org B", "org-b")
    user_a = create_user("a@example.com", "password123", "recruiter", org_a)
    user_b = create_user("b@example.com", "password123", "recruiter", org_b)
    request_a, _ = create_reference_request(token="org-a-token", organisation_id=org_a, created_by_user_id=user_a)
    request_b, token_b = create_reference_request(token="org-b-token", organisation_id=org_b, created_by_user_id=user_b)
    csrf = csrf_token(client.get(f"/reference/{token_b}"))
    client.post(f"/reference/{token_b}", data=valid_reference(csrf))
    reference_b = latest_reference_id()

    login_as(client, "a@example.com")
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"org-b-token" not in response.data

    assert client.get(f"/reference-request/{request_b}/timeline").status_code == 404
    assert client.get(f"/reference/{reference_b}/pdf").status_code == 404
    response = client.get("/dashboard")
    csrf = csrf_token(response)
    assert client.post(f"/reference-request/{request_b}/resend-email", data={"csrf_token": csrf}).status_code == 404
    assert request_a and request_b


def test_recruiter_cannot_access_super_admin_but_super_admin_can(client):
    org_id = create_org("Control Org", "control-org")
    create_user("recruiter@control.test", "password123", "recruiter", org_id)
    login_as(client, "recruiter@control.test")

    response = client.get("/super-admin")
    assert response.status_code == 403

    client.get("/logout")
    login(client)
    response = client.get("/super-admin")
    assert response.status_code == 200
    assert b"Super Admin" in response.data


def test_organisation_admin_cannot_create_super_admin(client):
    org_id = create_org("Admin Org", "admin-org")
    create_user("admin@org.test", "password123", "organisation_admin", org_id)
    response = login_as(client, "admin@org.test")
    csrf = csrf_token(response)

    response = client.post(
        "/organisation/users/create",
        data={
            "csrf_token": csrf,
            "email": "new@org.test",
            "role": "super_admin",
            "password": "password123",
        },
    )

    assert response.status_code == 302
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        role = connection.execute(
            "SELECT role FROM users WHERE email = ?",
            ("new@org.test",),
        ).fetchone()[0]
    assert role == "recruiter"
