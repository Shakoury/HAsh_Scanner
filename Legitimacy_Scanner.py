import requests
import re
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict
import ssl
import socket
import ipaddress
import unicodedata
import idna
from difflib import SequenceMatcher

class LegitimacyScanner:
    """
    Professional-grade website legitimacy & phishing detection scanner.
    False-positive minimized, CTF & real-world ready.
    """

    def __init__(self):
        self.timeout = 12
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        }

        self.legitimate_brands = {
            'paypal': 'paypal.com',
            'amazon': 'amazon.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'google': 'google.com',
            'facebook': 'facebook.com',
            'instagram': 'instagram.com',
            'github': 'github.com',
            'linkedin': 'linkedin.com'
        }

        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',
            '.click', '.pw', '.loan', '.bid'
        }

        self.phishing_keywords = {
            'verify account', 'confirm identity',
            'suspended account', 'urgent action required'
        }

    # --------------------------------------------------

    def scan(self, url: str) -> Dict:
        results = {
            'url': url,
            'risk_score': 0,
            'is_legitimate': True,
            'is_phishing': False,
            'risk_level': 'unknown',
            'indicators': {
                'positive': [],
                'warnings': [],
                'negative': [],
                'phishing': []
            },
            'details': {},
            'verdict': '',
            'recommendation': ''
        }

        try:
            scores = [
                self._check_domain(url, results),
                self._check_phishing(url, results),
                self._check_ssl(url, results),
                self._check_content(url, results),
            ]

            total = min(100, sum(scores))
            results['risk_score'] = total

            # FINAL VERDICT (requires multiple signals)
            if results['is_phishing'] and total >= 60:
                results['risk_level'] = 'critical'
                results['is_legitimate'] = False
                results['verdict'] = '🚨 CONFIRMED PHISHING'
                results['recommendation'] = 'Do NOT interact. Report immediately.'

            elif total >= 45:
                results['risk_level'] = 'high'
                results['is_legitimate'] = False
                results['verdict'] = '⚠️ HIGH RISK'
                results['recommendation'] = 'Avoid entering sensitive data.'

            elif total >= 25:
                results['risk_level'] = 'medium'
                results['verdict'] = '⚡ SUSPICIOUS'
                results['recommendation'] = 'Verify through official sources.'

            else:
                results['risk_level'] = 'low'
                results['verdict'] = '✅ LIKELY LEGITIMATE'
                results['recommendation'] = 'No major red flags detected.'

        except Exception as e:
            results['verdict'] = '❓ ANALYSIS FAILED'
            results['details']['error'] = str(e)

        return results

    # --------------------------------------------------

    def _check_phishing(self, url: str, results: Dict) -> int:
        score = 0
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            return 0

        domain = domain.lower()

        # Brand impersonation (STRICT)
        for brand, legit_domain in self.legitimate_brands.items():
            if brand in domain:
                if domain != legit_domain and not domain.endswith("." + legit_domain):
                    score += 35
                    results['is_phishing'] = True
                    results['indicators']['phishing'].append(
                        f'Fake {brand.title()} domain'
                    )

        # Typosquatting (DOMAIN ONLY)
        for legit in self.legitimate_brands.values():
            similarity = SequenceMatcher(None, domain, legit).ratio()
            if 0.80 < similarity < 0.95:
                score += 20
                results['indicators']['warnings'].append(
                    f'Domain similar to {legit}'
                )

        # @ symbol phishing trick
        if '@' in url:
            score += 25
            results['is_phishing'] = True
            results['indicators']['phishing'].append('URL contains @ symbol')

        return score

    # --------------------------------------------------

    def _check_domain(self, url: str, results: Dict) -> int:
        score = 0
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            return 25

        # IP instead of domain
        try:
            ipaddress.ip_address(domain)
            score += 15
            results['indicators']['warnings'].append('IP address used')
        except ValueError:
            pass

        # Unicode homograph (punycode-safe)
        try:
            decoded = idna.decode(domain)
            scripts = {
                unicodedata.name(c).split()[0]
                for c in decoded if c.isalpha()
            }
            if len(scripts) > 1:
                score += 20
                results['indicators']['warnings'].append(
                    'Potential homograph domain'
                )
        except Exception:
            pass

        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 15
                results['indicators']['warnings'].append(
                    f'Suspicious TLD {tld}'
                )

        # WHOIS age
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]

            if isinstance(created, datetime):
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - created).days
                results['details']['domain_age_days'] = age

                if age < 14:
                    score += 20
                elif age < 90:
                    score += 8
                elif age > 365:
                    results['indicators']['positive'].append(
                        'Established domain'
                    )
        except Exception:
            results['indicators']['warnings'].append('WHOIS unavailable')

        return score

    # --------------------------------------------------

    def _check_ssl(self, url: str, results: Dict) -> int:
        parsed = urlparse(url)
        score = 0

        if parsed.scheme != 'https':
            score += 15
            results['indicators']['warnings'].append('No HTTPS')

        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname):
                    results['indicators']['positive'].append(
                        'Valid SSL certificate'
                    )
        except Exception:
            score += 10
            results['indicators']['warnings'].append(
                'SSL validation inconclusive'
            )

        return score

    # --------------------------------------------------

    def _check_content(self, url: str, results: Dict) -> int:
        score = 0

        try:
            r = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )

            soup = BeautifulSoup(r.text, 'html.parser')

            # Ignore code blocks
            for tag in soup(['script', 'style', 'code', 'pre']):
                tag.decompose()

            text = soup.get_text(" ").lower()

            matches = [k for k in self.phishing_keywords if k in text]
            if len(matches) >= 2:
                score += 20
                results['is_phishing'] = True
                results['indicators']['phishing'].append(
                    'Phishing language detected'
                )

            forms = soup.find_all('form')
            if forms and len(text) < 600:
                score += 10
                results['indicators']['warnings'].append(
                    'Minimal content with forms'
                )

        except Exception:
            results['indicators']['warnings'].append(
                'Content scan failed'
            )

        return score
