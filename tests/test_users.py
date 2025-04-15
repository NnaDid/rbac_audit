from conftest import client 


def test_login_user(client:client):
    response = client.post("/login", data={
        "username": "Prince Chiemeka",
        "password": "999999"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()
