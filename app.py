from flask import Flask, request, render_template_string
from enhanced_scanner import EnhancedScanner
import re
from urllib.parse import urlparse
from security_middleware import SecurityMiddleware
import time

app = Flask(__name__)
scanner = EnhancedScanner()
security = SecurityMiddleware()
security.init_app(app)

# Secure session config
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# -----------------------------
# Simple in-memory rate limiter
# -----------------------------
RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 5      # requests per window

def is_rate_limited(ip):
    now = time.time()
    window = RATE_LIMIT.get(ip, [])
    window = [t for t in window if now - t < RATE_LIMIT_WINDOW]
    if len(window) >= RATE_LIMIT_MAX:
        RATE_LIMIT[ip] = window
        return True
    window.append(now)
    RATE_LIMIT[ip] = window
    return False


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGLIX SHIELD</title>

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800;900&display=swap');

* { margin:0; padding:0; box-sizing:border-box; }

body {
    font-family: 'Inter', sans-serif;
    background:#0a0a0a;
    color:#eaeaea;
    min-height:100vh;
}

body::before {
    content:'';
    position:fixed;
    inset:0;
    background:
      linear-gradient(rgba(0,255,157,.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,157,.03) 1px, transparent 1px);
    background-size:50px 50px;
    pointer-events:none;
}

.container {
    max-width:1400px;
    margin:auto;
    padding:80px 40px;
}

h1 {
    text-align:center;
    font-size:4rem;
    font-weight:900;
    background:linear-gradient(135deg,#fff,#00ff9d);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
    text-transform:uppercase;
}

.subtitle {
    text-align:center;
    color:#888;
    letter-spacing:.15em;
    margin-bottom:60px;
}

.scan-box, .card {
    background:rgba(18,18,18,.6);
    border:1px solid rgba(0,255,157,.15);
    backdrop-filter:blur(40px);
    border-radius:20px;
    padding:40px;
    margin-bottom:40px;
}

.input-row {
    display:flex;
    gap:16px;
}

input {
    flex:1;
    padding:18px;
    background:#000;
    border:2px solid rgba(0,255,157,.3);
    border-radius:12px;
    color:#fff;
}

button {
    padding:18px 36px;
    font-weight:800;
    background:#00ff9d;
    border:none;
    border-radius:12px;
    cursor:pointer;
}

.metric-grid {
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
    gap:20px;
}

.metric {
    background:#000;
    padding:28px;
    border-radius:16px;
    border:1px solid rgba(0,255,157,.2);
    text-align:center;
}

.metric span {
    display:block;
    font-size:2.4rem;
    font-weight:900;
    color:#00ff9d;
}

.indicator {
    padding:18px;
    border-radius:12px;
    margin-bottom:12px;
}

.pos { border-left:4px solid #00ff9d; color:#00ff9d; }
.warn { border-left:4px solid #ffea00; color:#ffea00; }
.neg { border-left:4px solid #ff0055; color:#ff0055; }
.phish { border-left:4px solid #ff00ff; color:#ff00ff; }

.error {
    background:rgba(255,0,85,.1);
    border:1px solid rgba(255,0,85,.3);
    padding:28px;
    border-radius:16px;
    text-align:center;
}
</style>
</head>
<body>

<div class="container">
<h1>AEGLIX SHIELD</h1>
<p class="subtitle">Advanced Website Trust & Phishing Defense</p>

<div class="scan-box">
<form method="post">
<div class="input-row">
<input name="url" placeholder="https://example.com" value="{{ url|e }}" required>
<button>SCAN</button>
</div>
</form>
</div>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

{% if results %}
<div class="card">

<div class="metric-grid">
<div class="metric">Risk Score<span>{{ results.risk_score }}/100</span></div>
<div class="metric">Risk Level<span>{{ results.risk_level|title }}</span></div>
<div class="metric">Confidence<span>{{ results.confidence|title }}</span></div>
</div>

<h3 style="margin-top:40px;">Security Indicators</h3>

{% for i in results.indicators.phishing %}
<div class="indicator phish">{{ i }}</div>
{% endfor %}

{% for i in results.indicators.negative %}
<div class="indicator neg">{{ i }}</div>
{% endfor %}

{% for i in results.indicators.warnings %}
<div class="indicator warn">{{ i }}</div>
{% endfor %}

{% for i in results.indicators.positive %}
<div class="indicator pos">{{ i }}</div>
{% endfor %}

</div>
{% endif %}
</div>
</body>
</html>
"""


def validate_url(url):
    if not re.match(r'^https?://', url):
        return None, "URL must start with http:// or https://"

    parsed = urlparse(url)
    if not parsed.hostname or '.' not in parsed.hostname:
        return None, "Invalid domain"

    return url, None


@app.route('/', methods=['GET', 'POST'])
@security.protect
def index():
    url = ""
    results = None
    error = None

    if request.method == 'POST':
        ip = request.remote_addr
        if is_rate_limited(ip):
            error = "Too many scans. Please wait a minute."
        else:
            url = request.form.get('url', '').strip()
            valid, err = validate_url(url)
            if err:
                error = err
            else:
                try:
                    results = scanner.scan(valid)
                except Exception:
                    error = "Scan failed. Site unreachable or blocked."

    return render_template_string(
        HTML_TEMPLATE,
        url=url,
        results=results,
        error=error
    )


@app.after_request
def security_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'none'; object-src 'none';"
    )
    return resp


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
