from flask import Flask, request, render_template_string
from enhanced_scanner import EnhancedScanner
import re
from urllib.parse import urlparse
from security_middleware import SecurityMiddleware


app = Flask(__name__)
scanner = EnhancedScanner()
security = SecurityMiddleware()
security.init_app(app)  # ← Initialize

# Security: Set secure session configuration
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; script-src 'none';">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="X-XSS-Protection" content="1; mode=block">
<title>Website Legitimacy Scanner</title>
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
        color: #e0e6ed;
        min-height: 100vh;
        overflow-x: hidden;
        position: relative;
    }

    body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            radial-gradient(circle at 20% 30%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 80% 70%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
        pointer-events: none;
        z-index: 0;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 60px 20px;
        position: relative;
        z-index: 1;
    }

    header {
        text-align: center;
        margin-bottom: 50px;
    }

    h1 {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 15px;
        letter-spacing: -0.02em;
    }

    .subtitle {
        font-size: 1.1rem;
        color: #94a3b8;
        font-weight: 400;
    }

    .scan-section {
        background: rgba(30, 41, 59, 0.5);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 24px;
        padding: 40px;
        margin-bottom: 40px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }

    .input-container {
        display: flex;
        gap: 12px;
        max-width: 700px;
        margin: 0 auto;
    }

    input[type="text"] {
        flex: 1;
        padding: 18px 24px;
        font-size: 1rem;
        background: rgba(15, 23, 42, 0.6);
        border: 2px solid rgba(148, 163, 184, 0.2);
        border-radius: 16px;
        color: #e0e6ed;
        outline: none;
        transition: all 0.3s ease;
    }

    input[type="text"]:focus {
        border-color: #60a5fa;
        box-shadow: 0 0 0 4px rgba(96, 165, 250, 0.1);
    }

    input[type="text"]::placeholder {
        color: #64748b;
    }

    .scan-btn {
        padding: 18px 36px;
        font-size: 1rem;
        font-weight: 600;
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
        border: none;
        border-radius: 16px;
        color: white;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 8px 24px rgba(59, 130, 246, 0.3);
    }
        
        .reset-btn {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border: none;
            padding: 16px 32px;
            font-size: 18px;
            font-weight: 600;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 4px 15px rgba(245, 87, 108, 0.4);
            margin-left: 10px;
            text-decoration: none;
            user-select: none;
        }
        
        .reset-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(245, 87, 108, 0.6);
        }

    .scan-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 12px 32px rgba(59, 130, 246, 0.4);
    }

    .scan-btn:active {
        transform: translateY(0);
    }

    .results-card {
        background: rgba(30, 41, 59, 0.5);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 24px;
        padding: 40px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        animation: slideIn 0.5s ease;
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .verdict-header {
        text-align: center;
        margin-bottom: 40px;
        padding-bottom: 30px;
        border-bottom: 1px solid rgba(148, 163, 184, 0.1);
    }

    .verdict-title {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 20px;
    }

    .verdict-critical { color: #ef4444; }
    .verdict-high { color: #f97316; }
    .verdict-medium { color: #eab308; }
    .verdict-low { color: #22c55e; }

    .metrics {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 40px;
    }

    .metric-card {
        background: rgba(15, 23, 42, 0.4);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 16px;
        padding: 20px;
        text-align: center;
    }

    .metric-label {
        font-size: 0.875rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
    }

    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #e0e6ed;
    }

    .risk-bar-container {
        margin: 30px 0;
    }

    .risk-bar-label {
        display: flex;
        justify-content: space-between;
        margin-bottom: 10px;
        font-size: 0.875rem;
        color: #94a3b8;
    }

    .risk-bar {
        height: 12px;
        background: rgba(15, 23, 42, 0.6);
        border-radius: 10px;
        overflow: hidden;
        position: relative;
    }

    .risk-bar-fill {
        height: 100%;
        border-radius: 10px;
        transition: width 1s ease, background 0.3s ease;
    }

    .risk-critical { background: linear-gradient(90deg, #ef4444, #dc2626); }
    .risk-high { background: linear-gradient(90deg, #f97316, #ea580c); }
    .risk-medium { background: linear-gradient(90deg, #eab308, #ca8a04); }
    .risk-low { background: linear-gradient(90deg, #22c55e, #16a34a); }

    .section {
        margin-bottom: 40px;
    }

    .section-title {
        font-size: 1.25rem;
        font-weight: 600;
        margin-bottom: 20px;
        color: #e0e6ed;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .section-title::before {
        content: '';
        width: 4px;
        height: 24px;
        background: linear-gradient(180deg, #60a5fa, #8b5cf6);
        border-radius: 2px;
    }

    .indicators-grid {
        display: grid;
        gap: 12px;
    }

    .indicator {
        background: rgba(15, 23, 42, 0.4);
        border-left: 3px solid;
        border-radius: 12px;
        padding: 16px 20px;
        font-size: 0.95rem;
        transition: all 0.3s ease;
        word-wrap: break-word;
    }

    .indicator:hover {
        background: rgba(15, 23, 42, 0.6);
        transform: translateX(4px);
    }

    .indicator-positive {
        border-color: #22c55e;
        color: #86efac;
    }

    .indicator-warning {
        border-color: #eab308;
        color: #fde047;
    }

    .indicator-negative {
        border-color: #ef4444;
        color: #fca5a5;
    }

    .indicator-phishing {
        border-color: #ec4899;
        color: #f9a8d4;
        background: rgba(236, 72, 153, 0.1);
    }

    .recommendation {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1));
        border: 1px solid rgba(96, 165, 250, 0.3);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        font-size: 1.05rem;
        font-weight: 500;
        line-height: 1.6;
    }

    .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: #64748b;
    }

    .empty-state svg {
        width: 120px;
        height: 120px;
        margin-bottom: 20px;
        opacity: 0.5;
    }

    .error-message {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 16px;
        padding: 20px;
        margin-bottom: 20px;
        color: #fca5a5;
        text-align: center;
    }

    .error-title {
        font-size: 1.5rem;
        font-weight: 700;
        margin-bottom: 10px;
        color: #ef4444;
    }

    @media (max-width: 768px) {
        h1 {
            font-size: 2rem;
        }

        .input-container {
            flex-direction: column;
        }

        .metrics {
            grid-template-columns: 1fr;
        }
    }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Website Legitimacy Scanner</h1>
        <p class="subtitle">Advanced phishing detection & security analysis</p>
    </header>

    <div class="scan-section">
        <form method="get" id="scanForm">
            <div class="input-container">
                <input 
                    type="text" 
                    name="url" 
                    id="urlInput"
                    placeholder="Enter website URL (e.g., https://example.com)"
                    value="{{ url | e }}"
                    required
                    maxlength="2048"
                >
                <button type="submit" class="scan-btn">Scan Now</button>
                <a href="/" class="reset-btn">
                    <span class="scan-icon">🔄</span>
                    Reset
                </a>
            </div>
        </form>
    </div>

    {% if error %}
    <div class="error-message">
        <div class="error-title">⚠️ Invalid Input</div>
        {{ error | e }}
    </div>
    {% endif %}

    {% if results %}
    <div class="results-card">
        <div class="verdict-header">
            <div class="verdict-title verdict-{{ results.risk_level | e }}">
                {{ results.verdict | e }}
            </div>
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{{ results.risk_score | int }}/100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confidence</div>
                <div class="metric-value">{{ results.confidence | title | e }}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value">{{ results.risk_level | title | e }}</div>
            </div>
            {% if results.is_phishing %}
            <div class="metric-card">
                <div class="metric-label">Phishing</div>
                <div class="metric-value" style="color: #ec4899;">Detected</div>
            </div>
            {% endif %}
        </div>

        <div class="risk-bar-container">
            <div class="risk-bar-label">
                <span>Risk Assessment</span>
                <span>{{ results.risk_score | int }}%</span>
            </div>
            <div class="risk-bar">
                <div class="risk-bar-fill risk-{{ results.risk_level | e }}" style="width: {{ results.risk_score | int }}%"></div>
            </div>
        </div>

        {% if results.indicators.positive or results.indicators.warnings or results.indicators.negative or results.indicators.phishing %}
        <div class="section">
            <h3 class="section-title">Security Indicators</h3>
            <div class="indicators-grid">
                {% for item in results.indicators.phishing %}
                <div class="indicator indicator-phishing">{{ item | e }}</div>
                {% endfor %}
                {% for item in results.indicators.negative %}
                <div class="indicator indicator-negative">{{ item | e }}</div>
                {% endfor %}
                {% for item in results.indicators.warnings %}
                <div class="indicator indicator-warning">{{ item | e }}</div>
                {% endfor %}
                {% for item in results.indicators.positive %}
                <div class="indicator indicator-positive">{{ item | e }}</div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h3 class="section-title">Recommendation</h3>
            <div class="recommendation">
                {{ results.recommendation | e }}
            </div>
        </div>
    </div>
    {% else %}
    {% if not error %}
    <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
        <h3 style="color: #94a3b8; margin-bottom: 10px;">Enter a URL to begin scanning</h3>
        <p>Analyze websites for phishing, scams, and security vulnerabilities</p>
    </div>
    {% endif %}
    {% endif %}
</div>
</body>
</html>"""

def validate_url(url):
    """Strict URL validation - reject anything that's not a proper URL"""
    if not url:
        return None, "URL is required"
    
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Length check
    if len(url) > 2048:
        return None, "URL is too long (maximum 2048 characters)"
    
    # Check for HTML/script tags - instant rejection
    dangerous_patterns = [
        '<script', '</script>', '<img', '<iframe', '<object', '<embed',
        'onerror=', 'onload=', 'onclick=', 'javascript:', 'vbscript:',
        'data:text/html', '<svg', '<body', '<html', 'onfocus=', 'onmouseover='
    ]
    
    url_lower = url.lower()
    for pattern in dangerous_patterns:
        if pattern in url_lower:
            return None, f"Invalid input detected. Please enter a valid website URL only."
    
    # Must start with http:// or https:// or be a domain name
    has_protocol = url.startswith(('http://', 'https://'))
    
    if not has_protocol:
        # Check if it looks like a domain before adding protocol
        # Must contain at least one dot and valid characters
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'  # subdomain or domain
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'  # more domains
            r'\.[a-zA-Z]{2,}$'  # TLD
        )
        
        # Extract just the domain part (before any path/query)
        domain_part = url.split('/')[0].split('?')[0].split('#')[0]
        
        if not domain_pattern.match(domain_part):
            return None, "Invalid URL format. Please enter a valid domain name (e.g., example.com) or full URL (e.g., https://example.com)"
        
        url = 'https://' + url
    
    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception:
        return None, "Unable to parse URL. Please check the format."
    
    # Verify scheme is http or https
    if parsed.scheme not in ['http', 'https']:
        return None, f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are allowed."
    
    # Must have a hostname
    if not parsed.hostname:
        return None, "Invalid URL: No hostname found"
    
    # Hostname validation - must be valid domain or IP
    hostname = parsed.hostname.lower()
    
    # Check for obviously invalid hostnames
    if len(hostname) < 1 or len(hostname) > 253:
        return None, "Invalid hostname length"
    
    # Reject if hostname contains only special characters or numbers
    if not re.search(r'[a-zA-Z]', hostname):
        return None, "Invalid hostname format"
    
    # Additional validation for domain format
    # Must have at least one dot (unless localhost) or be a valid IP
    if hostname != 'localhost':
        # Check if it's an IP address
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(hostname):
            # Validate IP ranges
            parts = hostname.split('.')
            if not all(0 <= int(part) <= 255 for part in parts):
                return None, "Invalid IP address"
        else:
            # Must be a domain with at least one dot
            if '.' not in hostname:
                return None, "Invalid domain format. Domains must contain at least one dot (e.g., example.com)"
            
            # Validate TLD
            tld = hostname.split('.')[-1]
            if len(tld) < 2:
                return None, "Invalid top-level domain"
            
            if not re.match(r'^[a-z]{2,}$', tld):
                return None, "Invalid top-level domain format"
    
    # Final comprehensive validation
    full_url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)?$',  # optional path
        re.IGNORECASE
    )
    
    if not full_url_pattern.match(url):
        return None, "Invalid URL format. Please enter a valid website URL (e.g., https://example.com)"
    
    return url, None

@app.route('/', methods=['GET'])
@security.protect
def index():
    url = request.args.get('url', '').strip()
    results = None
    error = None
    original_input = url  # Store original for display
    
    if url:
        # Validate URL with strict checks
        validated_url, error_msg = validate_url(url)
        
        if error_msg:
            error = error_msg
            url = original_input  # Show what they entered
        else:
            try:
                # Scan the URL
                results = scanner.scan(validated_url)
                url = validated_url
            except Exception as e:
                error = "An error occurred while scanning the URL. The site may be unreachable or invalid."
                # Log the error for debugging (in production, use proper logging)
                app.logger.error(f"Scan error for {validated_url}: {str(e)}")
    
    return render_template_string(HTML_TEMPLATE, url=url or '', results=results, error=error)

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; object-src 'none';"
    return response

if __name__ == '__main__':
    # Security: Disable debug mode in production
    app.run(host='0.0.0.0', port=5000, debug=False)
