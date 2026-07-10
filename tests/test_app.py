import sqlite3
import re
from contextlib import closing

import pytest

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
    }


def create_reference_request(token="secure-token", status="pending"):
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
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "Alex Candidate",
                "Robin Referee",
                "robin@example.com",
                "Reference Hospital",
                "Nurse",
                token,
                status,
            ))
    return cursor.lastrowid, token


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


def test_public_submit_is_disabled(client):
    response = client.post("/submit", data={})

    assert response.status_code == 403
    assert b"Public submissions are disabled" in response.data


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


def test_reference_submission_rejects_invalid_rating(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_reference(csrf)
    data["clinical_competence"] = "Magic"

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 400
    assert b"Clinical Competence must be a valid rating." in response.data


def test_completed_token_cannot_be_reused(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = client.get(f"/reference/{request_token}")

    assert response.status_code == 403
    assert b"already been submitted" in response.data


def test_dashboard_displays_records_after_login(client):
    _, request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = login(client)

    assert response.status_code == 200
    assert b"Alex Candidate" in response.data
    assert b"Total References" in response.data


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
