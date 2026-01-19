"""
security_middleware.py
Plug-and-play DDoS protection for Flask apps
Just import and apply - no need to modify existing code!
"""

from flask import request, jsonify, render_template_string
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib


class SecurityMiddleware:
    """
    Complete security middleware for Flask
    Handles rate limiting, DDoS protection, and security headers
    """
    
    def __init__(self, app=None):
        self.app = app
        
        # Rate limiting storage
        self.requests = defaultdict(list)
        self.blacklist = set()
        self.suspicious_ips = defaultdict(int)
        
        # Configuration
        self.config = {
            'requests_per_minute': 15,
            'requests_per_hour': 100,
            'requests_per_day': 500,
            'auto_blacklist_threshold': 3,
            'cleanup_interval': 100,
        }
        
        self.request_count = 0
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        
        # Register after_request handler for security headers
        @app.after_request
        def add_security_headers(response):
            return self._add_security_headers(response)
        
        print("🛡️  Security Middleware: ACTIVE")
        print(f"   • Rate Limit: {self.config['requests_per_minute']} req/min")
        print(f"   • DDoS Protection: Enabled")
        print(f"   • Security Headers: Enabled")
    
    def _get_client_ip(self):
        """Get real client IP (handles proxies)"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr or 'unknown'
    
    def _hash_ip(self, ip):
        """Hash IP for privacy in logs"""
        return hashlib.sha256(ip.encode()).hexdigest()[:16]
    
    def _cleanup_old_requests(self, ip):
        """Remove requests older than 24 hours"""
        if ip in self.requests:
            cutoff = datetime.now() - timedelta(days=1)
            self.requests[ip] = [ts for ts in self.requests[ip] if ts > cutoff]
    
    def _check_rate_limit(self, ip):
        """
        Check if IP has exceeded rate limits
        Returns: (allowed: bool, retry_after: int, reason: str)
        """
        # Check blacklist
        if ip in self.blacklist:
            return False, 3600, "IP blacklisted"
        
        now = datetime.now()
        
        # Periodic cleanup
        self.request_count += 1
        if self.request_count % self.config['cleanup_interval'] == 0:
            self._cleanup_old_requests(ip)
        
        timestamps = self.requests[ip]
        
        # Per-minute check
        minute_ago = now - timedelta(minutes=1)
        recent = sum(1 for ts in timestamps if ts > minute_ago)
        if recent >= self.config['requests_per_minute']:
            return False, 60, f"Exceeded {self.config['requests_per_minute']} requests/minute"
        
        # Per-hour check
        hour_ago = now - timedelta(hours=1)
        hourly = sum(1 for ts in timestamps if ts > hour_ago)
        if hourly >= self.config['requests_per_hour']:
            return False, 300, f"Exceeded {self.config['requests_per_hour']} requests/hour"
        
        # Per-day check
        day_ago = now - timedelta(days=1)
        daily = sum(1 for ts in timestamps if ts > day_ago)
        if daily >= self.config['requests_per_day']:
            # Auto-blacklist if way over limit
            if daily > self.config['requests_per_day'] * 1.5:
                self.blacklist.add(ip)
                print(f"🚫 Auto-blacklisted IP: {self._hash_ip(ip)}")
            return False, 3600, f"Exceeded {self.config['requests_per_day']} requests/day"
        
        # Allow request
        self.requests[ip].append(now)
        return True, 0, "OK"
    
    def _check_suspicious_activity(self, ip):
        """Detect suspicious patterns"""
        suspicious_score = 0
        
        # Check User-Agent
        user_agent = request.headers.get('User-Agent', '').lower()
        suspicious_agents = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests']
        
        if not user_agent:
            suspicious_score += 3
        elif any(agent in user_agent for agent in suspicious_agents):
            suspicious_score += 2
        
        # Check for path traversal attempts
        url = request.url.lower()
        suspicious_patterns = ['..', '//', 'admin', 'wp-admin', 'phpmyadmin', '.env', '.git']
        if any(pattern in url for pattern in suspicious_patterns):
            suspicious_score += 5
        
        # Track and block
        if suspicious_score >= 5:
            self.suspicious_ips[ip] += 1
            
            if self.suspicious_ips[ip] >= self.config['auto_blacklist_threshold']:
                self.blacklist.add(ip)
                print(f"🚫 Blocked suspicious IP: {self._hash_ip(ip)}")
                return False
        
        return ip not in self.blacklist
    
    def _add_security_headers(self, response):
        """Add security headers to response"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'none';"
        
        # Rate limit info headers
        ip = self._get_client_ip()
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        recent = sum(1 for ts in self.requests.get(ip, []) if ts > minute_ago)
        
        response.headers['X-RateLimit-Limit'] = str(self.config['requests_per_minute'])
        response.headers['X-RateLimit-Remaining'] = str(max(0, self.config['requests_per_minute'] - recent))
        
        return response
    
    def _render_rate_limit_error(self, retry_after, reason):
        """Render user-friendly rate limit error page"""
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rate Limit Exceeded</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: 'Inter', -apple-system, sans-serif;
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
        color: #e0e6ed;
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        padding: 20px;
    }
    .error-container {
        background: rgba(30, 41, 59, 0.6);
        backdrop-filter: blur(20px);
        border: 2px solid rgba(239, 68, 68, 0.3);
        border-radius: 24px;
        padding: 50px 40px;
        text-align: center;
        max-width: 600px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    }
    h1 {
        font-size: 3rem;
        margin-bottom: 20px;
    }
    h2 {
        color: #ef4444;
        font-size: 1.8rem;
        margin-bottom: 20px;
    }
    p {
        color: #94a3b8;
        line-height: 1.8;
        margin-bottom: 15px;
        font-size: 1.1rem;
    }
    .retry-time {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 12px;
        padding: 20px;
        margin: 25px 0;
    }
    .time {
        font-size: 2.5rem;
        font-weight: 700;
        color: #ef4444;
    }
    .reason {
        background: rgba(15, 23, 42, 0.6);
        border-left: 4px solid #eab308;
        padding: 15px 20px;
        border-radius: 8px;
        margin-top: 20px;
        text-align: left;
    }
    .info {
        margin-top: 30px;
        font-size: 0.95rem;
        color: #64748b;
    }
</style>
</head>
<body>
<div class="error-container">
    <h1>⚠️</h1>
    <h2>Rate Limit Exceeded</h2>
    <p>You've made too many requests to our server.</p>
    
    <div class="retry-time">
        <div>Please wait</div>
        <div class="time">{{ retry_after }}s</div>
        <div>before trying again</div>
    </div>
    
    <div class="reason">
        <strong>Reason:</strong> {{ reason }}
    </div>
    
    <div class="info">
        <p>This protection ensures fair access for all users and prevents abuse.</p>
        <p>If you believe this is an error, please contact support.</p>
    </div>
</div>
</body>
</html>
        """, retry_after=retry_after, reason=reason), 429
    
    def protect(self, f):
        """
        Decorator to protect routes
        Usage: @security.protect
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = self._get_client_ip()
            
            # Check for suspicious activity
            if not self._check_suspicious_activity(ip):
                return jsonify({
                    'error': 'Blocked',
                    'message': 'Suspicious activity detected'
                }), 403
            
            # Check rate limit
            allowed, retry_after, reason = self._check_rate_limit(ip)
            
            if not allowed:
                return self._render_rate_limit_error(retry_after, reason)
            
            # Allow request
            return f(*args, **kwargs)
        
        return decorated_function
    
    def get_stats(self, ip=None):
        """Get statistics for monitoring"""
        if ip is None:
            ip = self._get_client_ip()
        
        now = datetime.now()
        timestamps = self.requests.get(ip, [])
        
        return {
            'ip_hash': self._hash_ip(ip),
            'requests_last_minute': sum(1 for ts in timestamps if ts > now - timedelta(minutes=1)),
            'requests_last_hour': sum(1 for ts in timestamps if ts > now - timedelta(hours=1)),
            'requests_today': sum(1 for ts in timestamps if ts > now - timedelta(days=1)),
            'is_blacklisted': ip in self.blacklist,
            'suspicious_score': self.suspicious_ips.get(ip, 0),
            'total_ips_tracked': len(self.requests),
            'total_blacklisted': len(self.blacklist),
        }


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def create_security_middleware(app, **config):
    """
    Quick setup function
    
    Usage:
        from security_middleware import create_security_middleware
        security = create_security_middleware(app, requests_per_minute=20)
    """
    middleware = SecurityMiddleware(app)
    
    # Apply custom config
    if config:
        middleware.config.update(config)
    
    return middleware


# ============================================
# STANDALONE INSTANCE (for easy import)
# ============================================

# Create a default instance that can be imported directly
security = SecurityMiddleware()


if __name__ == "__main__":
    # Demo/test mode
    from flask import Flask
    
    app = Flask(__name__)
    sec = SecurityMiddleware(app)
    
    @app.route('/')
    @sec.protect  # Protected route
    def home():
        stats = sec.get_stats()
        return f"""
        <h1>🛡️ Protected Route</h1>
        <p>IP Hash: {stats['ip_hash']}</p>
        <p>Requests (last min): {stats['requests_last_minute']}/15</p>
        <p>Requests (last hour): {stats['requests_last_hour']}/100</p>
        <p>Requests (today): {stats['requests_today']}/500</p>
        <p>Status: {"⚠️ Blacklisted" if stats['is_blacklisted'] else "✅ OK"}</p>
        """
    
    @app.route('/unprotected')
    def unprotected():
        return "<h1>This route has no protection</h1>"
    
    @app.route('/stats')
    @sec.protect
    def stats():
        return sec.get_stats()
    
    print("\n" + "="*70)
    print("SECURITY MIDDLEWARE - TEST MODE")
    print("="*70)
    print("\nProtected routes:")
    print("  • http://localhost:5000/       (rate limited)")
    print("  • http://localhost:5000/stats  (rate limited)")
    print("\nUnprotected routes:")
    print("  • http://localhost:5000/unprotected")
    print("\nTry making 20+ rapid requests to see rate limiting!")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
