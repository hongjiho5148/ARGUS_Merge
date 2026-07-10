import httpx

login_url = "http://localhost:8080/api/v1/auth/login"
upload_url = "http://localhost:8080/api/v1/posts"
data = {
    "title": "sample",
    "content": "sample",
    "type": "REVIEW",
    "rating": "20"
}

with httpx.Client() as client:
    resp = client.post(login_url, json={"email": "yerin@travel.com", "password": "12341234a"})
    resp.raise_for_status()
    token = resp.cookies.get("accessToken")
    
    files = {'images': ('test.jpg', b'dummy content', 'image/jpeg')}
    resp2 = client.post(upload_url, data=data, files=files, cookies={"accessToken": token})
    print(f"Status: {resp2.status_code}")
    print(f"Body: {resp2.text}")
