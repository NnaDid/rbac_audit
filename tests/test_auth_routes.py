from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_login_success():
    # Assumes user "admin" with password "adminpass" exists
    response = client.post("/login", data={
        "username": "admin",
        "password": "myTestAdmin2025"
    })
    assert response.status_code == 200
    json = response.json()
    assert "access_token" in json
    assert json["user"]["username"] == "admin"
