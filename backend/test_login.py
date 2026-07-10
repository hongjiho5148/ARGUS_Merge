import httpx

login_url = "http://localhost:8080/api/v1/auth/login"
account = {"email": "test@test.com", "password": "testtest1"}

with httpx.Client(timeout=5.0) as client:
    print(f"Trying to post to {login_url}")
    resp = client.post(
        login_url,
        json={"email": account["email"], "password": account["password"]}
    )
    print(f"Status: {resp.status_code}")
    print(f"Cookies: {resp.cookies}")
    token = resp.cookies.get("accessToken")
    print(f"Token: {token}")
