"""
Test Suite for Distributed Environment REST API (v2)
-----------------------------------------------------
Uses Flask's built-in test client with pytest to verify API functionality.

Author: [Your Name]
Course: MSc Secure Software Development
Unit: 9
"""

import pytest
from distributed_environment_api_v2 import app, users, get_users


@pytest.fixture
def client():
    # Setup Flask test client
    with app.test_client() as client:
        # Reset global `users` list before each test
        users.clear()
        users.extend([
            {"name": "James", "age": 30, "occupation": "Network Engineer"},
            {"name": "Ann", "age": 32, "occupation": "Doctor"},
            {"name": "Jason", "age": 22, "occupation": "Web Developer"}
        ])
        yield client


def test_get_existing_user(client):
    response = client.get("/user/Ann")
    assert response.status_code == 200
    assert response.json == {"name": "Ann", "age": 32, "occupation": "Doctor"}


def test_get_non_existing_user(client):
    response = client.get("/user/Alice")
    assert response.status_code == 404
    assert response.json["message"] == "User 'Alice' not found."


def test_post_new_user_success(client):
    payload = {"age": 28, "occupation": "Analyst"}
    response = client.post("/user/Alice", json=payload)
    assert response.status_code == 201
    assert response.json == {"name": "Alice", "age": 28, "occupation": "Analyst"}


def test_post_existing_user_fails(client):
    payload = {"age": 35, "occupation": "Teacher"}
    response = client.post("/user/Ann", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json["message"]


def test_put_existing_user_updates(client):
    payload = {"age": 40, "occupation": "Surgeon"}
    response = client.put("/user/Ann", json=payload)
    assert response.status_code == 200
    assert response.json == {"name": "Ann", "age": 40, "occupation": "Surgeon"}


def test_put_new_user_creates(client):
    payload = {"age": 33, "occupation": "Lawyer"}
    response = client.put("/user/Alice", json=payload)
    assert response.status_code == 201
    assert response.json == {"name": "Alice", "age": 33, "occupation": "Lawyer"}


def test_delete_existing_user(client):
    response = client.delete("/user/Jason")
    assert response.status_code == 200
    assert response.json["message"] == "User 'Jason' deleted."
    assert not any(user["name"] == "Jason" for user in get_users())


def test_delete_non_existing_user(client):
    response = client.delete("/user/Unknown")
    assert response.status_code == 200
    assert response.json["message"] == "User 'Unknown' deleted."
