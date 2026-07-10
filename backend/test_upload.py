import httpx

login_url = "http://localhost:8080/api/v1/auth/login"
upload_url = "http://localhost:8080/api/v1/seller/accommodations?name=test&description=test&category=test&location=test"

with httpx.Client() as client:
    resp = client.post(login_url, json={"email": "zenithair@travel.com", "password": "12341234a"})
    resp.raise_for_status()
    token = resp.cookies.get("accessToken")
    
    files = {'thumbnail': ('test.jpg', b'dummy content', 'image/jpeg')}
    resp2 = client.post(upload_url, files=files, cookies={"accessToken": token})
    print(f"Status: {resp2.status_code}")
    print(f"Body: {resp2.text}")
