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
            return False, 3600, f"Exceeded {self.config['requests_per_hour']} requests/hour"

        # Per-day check
        day_ago = now - timedelta(days=1)
        daily = sum(1 for ts in timestamps if ts > day_ago)
        if daily >= self.config['requests_per_day']:
            return False, 86400, f"Exceeded {self.config['requests_per_day']} requests/day"

        # Record this request
        self.requests[ip].append(now)
        return True, 0, ""

    def _check_suspicious_activity(self, ip):
        """Detect suspicious patterns - ALLOWS BROWSERS"""
        suspicious_score = 0

        # Check User-Agent
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # Allow known browsers immediately
        browser_agents = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'android', 'iphone']
        if any(browser in user_agent for browser in browser_agents):
            return True
            
        # Block obvious bots
        bot_agents = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests']
        if any(agent in user_agent for agent in bot_agents):
            suspicious_score += 5

        # Check for path traversal attempts
        url = request.url.lower()
        suspicious_patterns = ['..', 'admin', 'wp-admin', 'phpmyadmin', '.env', '.git']
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
        """Add comprehensive security headers"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'none';"
        
        # Rate limit headers
        ip = self._get_client_ip()
        response.headers['X-RateLimit-Limit'] = str(self.config['requests_per_minute'])
        
        minute_ago = datetime.now() - timedelta(minutes=1)
        recent = sum(1 for ts in self.requests.get(ip, []) if ts > minute_ago)
        remaining = max(0, self.config['requests_per_minute'] - recent)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        
        return response

    def _render_rate_limit_error(self, retry_after, reason):
        """Render a user-friendly rate limit error"""
        return jsonify({
            'error': 'Rate Limit Exceeded',
            'message': reason,
            'retry_after': retry_after
        }), 429

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
        minute_ago = now - timedelta(minutes=1)
        
        timestamps = self.requests.get(ip, [])
        recent_requests = sum(1 for ts in timestamps if ts > minute_ago)

        return {
            'ip': self._hash_ip(ip),
            'recent_requests': recent_requests,
            'is_blacklisted': ip in self.blacklist,
            'suspicious_score': self.suspicious_ips.get(ip, 0)
        }
