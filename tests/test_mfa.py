from conftest import client
from test_user_routes import get_token

def test_enable_mfa(client):
    token = get_token(client)
    res = client.post("/user/create-mfa-pin", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert "MFA enabled successfully" in res.json()["message"]
