from conftest import client
from test_user_routes import get_token

def test_get_logs(client):
    token = get_token(client)
    res = client.get("/logs", headers={"Authorization": f"Bearer {token}"})
    if res.status_code == 403:
        assert res.json()["detail"] == "Not authorized"  # If role is not security
    elif res.status_code == 200:
        assert isinstance(res.json(), list)
