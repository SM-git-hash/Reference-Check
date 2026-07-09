import sqlite3
import re
from contextlib import closing

import pytest

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


def create_reference_request(token="secure-token"):
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
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
                "Alex Candidate",
                "Robin Referee",
                "robin@example.com",
                "Reference Hospital",
                "Nurse",
                token,
                "pending",
            ))
    return token


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
    request_token = create_reference_request()
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
    request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    data = valid_reference(csrf)
    data["clinical_competence"] = "Magic"

    response = client.post(f"/reference/{request_token}", data=data)

    assert response.status_code == 400
    assert b"Clinical Competence must be a valid rating." in response.data


def test_completed_token_cannot_be_reused(client):
    request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = client.get(f"/reference/{request_token}")

    assert response.status_code == 403
    assert b"already been submitted" in response.data


def test_dashboard_displays_records_after_login(client):
    request_token = create_reference_request()
    response = client.get(f"/reference/{request_token}")
    csrf = csrf_token(response)
    client.post(f"/reference/{request_token}", data=valid_reference(csrf))

    response = login(client)

    assert response.status_code == 200
    assert b"Alex Candidate" in response.data
    assert b"Total References" in response.data
