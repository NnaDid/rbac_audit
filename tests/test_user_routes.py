from conftest import client 
def get_token(client:client):
    res = client.post("/login", data={
        "username": "admin",
        "password": "myTestAdmin2025"
    })
    return res.json()["access_token"]

def test_get_user_profile(client):
    token = get_token(client)
    res = client.get("/user/profile", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert "username" in res.json()

def test_update_profile(client):
    token = get_token(client)
    res = client.post("/user/update-profile", headers={"Authorization": f"Bearer {token}"},
                      json={"email": "newemail@example.com", "phone": "1234567890"})
    assert res.status_code == 200
    assert res.json()["message"] == "Profile updated successfully"
