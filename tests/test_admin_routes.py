from conftest import client
from test_user_routes import get_token

def test_admin_create_user(client:client):
    token = get_token(client)
    res   = client.post("/admin/create-user", headers={"Authorization": f"Bearer {token}"}, json={"username": "test2user", "email": "test2@example.com", "phone": "08016111111", "password": "password123" })
    assert res.status_code == 200
    assert "User created successfully" in res.json()["message"]

def test_assign_role(client:client):
    token    = get_token(client) 
    res      = client.post("/admin/assign-role", headers={"Authorization": f"Bearer {token}"}, json={"username": "testuser", "role": "security"})
    assert res.status_code == 200
    assert "Role assigned successfully" in res.json()["message"]
