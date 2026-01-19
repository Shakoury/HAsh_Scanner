"""
Enhanced Legitimacy Scanner with ML-Learned Patterns
Integrates learned patterns from 156,422 real phishing URLs
"""

from Legitimacy_Scanner import LegitimacyScanner
from urllib.parse import urlparse
from typing import Dict
import json


class EnhancedScanner(LegitimacyScanner):
    """
    Enhanced scanner that applies ML-learned patterns
    from real-world phishing dataset
    """
    
    def __init__(self, patterns_file='learned_patterns.json'):
        super().__init__()
        self.learned_patterns = self._load_patterns(patterns_file)
    
    def _load_patterns(self, filename: str) -> Dict:
        """Load ML-learned patterns"""
        try:
            with open(filename, 'r') as f:
                patterns = json.load(f)
            
            print("✅ ML Patterns Loaded:")
            print(f"   • {len(patterns.get('brand_impersonation', []))} brand impersonation patterns")
            print(f"   • {len(patterns.get('path_indicators', []))} path indicator patterns")
            print(f"   • {len(patterns.get('structural_indicators', []))} structural patterns")
            
            return patterns
        except FileNotFoundError:
            print("⚠️  No ML patterns found. Run ml_pattern_learner.py first.")
            return {
                'brand_impersonation': [],
                'path_indicators': [],
                'structural_indicators': []
            }
    
    def scan(self, url: str) -> Dict:
        """
        Enhanced scan with ML patterns
        Overrides parent scan() method
        """
        # Run base scanner first
        results = super().scan(url)
        
        # Apply ML-learned patterns
        ml_score = self._apply_ml_patterns(url, results)
        
        # Add ML score to total
        results['risk_score'] = min(100, results['risk_score'] + ml_score)
        results['details']['ml_contribution'] = ml_score
        
        # Recalculate verdict with new score
        total = results['risk_score']
        
        if results['is_phishing'] or total >= 50:
            results['risk_level'] = 'critical'
            results['is_legitimate'] = False
            results['confidence'] = 'high'
            results['verdict'] = '🚨 DANGEROUS - Confirmed Phishing/Scam'
            results['recommendation'] = '⛔ DO NOT INTERACT - This site shows patterns common in phishing attacks.'
        
        elif total >= 35:
            results['risk_level'] = 'high'
            results['is_legitimate'] = False
            results['confidence'] = 'high'
            results['verdict'] = '⚠️ HIGH RISK - Likely Fraudulent'
            results['recommendation'] = '⚠️ DANGER - Multiple red flags detected. Do not provide any information.'
        
        elif total >= 20:
            results['risk_level'] = 'medium'
            results['is_legitimate'] = False
            results['confidence'] = 'medium'
            results['verdict'] = '⚡ SUSPICIOUS - Exercise Extreme Caution'
            results['recommendation'] = '⚡ WARNING - Verify through official channels before proceeding.'
        
        elif total >= 10:
            results['risk_level'] = 'low'
            results['is_legitimate'] = True
            results['confidence'] = 'medium'
            results['verdict'] = '✓ LIKELY SAFE - Minor Concerns'
            results['recommendation'] = '✓ Appears mostly legitimate with minor issues.'
        
        else:
            results['risk_level'] = 'low'
            results['is_legitimate'] = True
            results['confidence'] = 'high'
            results['verdict'] = '✅ APPEARS LEGITIMATE'
            results['recommendation'] = '✅ No major red flags detected.'
        
        return results
    
    def _apply_ml_patterns(self, url: str, results: Dict) -> int:
        """
        Apply all ML-learned patterns
        Returns additional risk score
        """
        score = 0
        parsed = urlparse(url)
        domain = (parsed.hostname or '').lower()
        path = parsed.path.lower()
        full_url = url.lower()
        
        # 1. BRAND IMPERSONATION (learned from 156K phishing URLs)
        for pattern in self.learned_patterns.get('brand_impersonation', []):
            brand = pattern['brand']
            
            if brand in full_url:
                # Check if it's the actual brand domain
                legitimate_domains = {
                    'paypal': ['paypal.com'],
                    'google': ['google.com', 'googleapis.com', 'gstatic.com'],
                    'amazon': ['amazon.com', 'amazonaws.com'],
                    'apple': ['apple.com', 'icloud.com'],
                    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
                    'facebook': ['facebook.com', 'fb.com'],
                    'twitter': ['twitter.com', 'x.com'],
                    'ebay': ['ebay.com'],
                    'chase': ['chase.com'],
                    'bank': [],  # Generic term
                    'secure': [],  # Generic term
                    'account': [],  # Generic term
                    'verify': [],  # Generic term
                }
                
                legit_domains = legitimate_domains.get(brand, [])
                
                # Check if domain matches legitimate
                is_legit = any(
                    domain == ld or 
                    domain.endswith('.' + ld)
                    for ld in legit_domains
                )
                
                if not is_legit and legit_domains:
                    # Brand found but not legitimate domain = PHISHING
                    score += pattern['score']
                    results['indicators']['phishing'].append(
                        f"🚨 ML: Fake {brand.title()} detected (learned pattern, appears in {pattern['frequency']:.1f}% of phishing)"
                    )
                    results['is_phishing'] = True
                
                elif not legit_domains:
                    # Generic suspicious terms (secure, account, verify, bank)
                    score += max(5, pattern['score'] // 2)
                    results['indicators']['warnings'].append(
                        f"⚠️ ML: Suspicious keyword '{brand}' (appears in {pattern['frequency']:.1f}% of phishing)"
                    )
        
        # 2. PATH INDICATORS (learned patterns in URL paths)
        path_matches = 0
        for pattern in self.learned_patterns.get('path_indicators', []):
            keyword = pattern['keyword']
            
            if keyword in path:
                path_matches += 1
                score += min(15, pattern['score'])
                
                # Only report top matches to avoid spam
                if path_matches <= 3:
                    results['indicators']['warnings'].append(
                        f"⚠️ ML: '{keyword}' in path (found in {pattern['frequency']:.1f}% of phishing)"
                    )
        
        # Bonus for multiple path indicators
        if path_matches >= 3:
            score += 15
            results['indicators']['negative'].append(
                f"🚩 ML: Multiple suspicious path keywords ({path_matches} detected)"
            )
        
        # 3. STRUCTURAL INDICATORS (learned from dataset)
        for pattern in self.learned_patterns.get('structural_indicators', []):
            indicator_type = pattern['type']
            
            if indicator_type == 'at_symbol' and '@' in url:
                score += pattern['score']
                results['indicators']['phishing'].append(
                    f"🚨 ML: @ symbol detected (found in {pattern['frequency']:.1f}% of phishing)"
                )
                results['is_phishing'] = True
        
        # Add note about ML contribution
        if score > 0:
            results['details']['ml_patterns_triggered'] = True
            results['indicators']['positive'].append(
                f"🤖 ML patterns from 156,422 real phishing URLs analyzed"
            )
        
        return score


# ============================================
# TEST THE ENHANCED SCANNER
# ============================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║        ENHANCED SCANNER WITH ML PATTERNS - TEST                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Initialize enhanced scanner
    scanner = EnhancedScanner()
    
    print("\n" + "="*70)
    print("TESTING ENHANCED SCANNER")
    print("="*70)
    
    # Test URLs
    test_cases = [
        ("https://secure-paypal-login.com/verify", "Fake PayPal (should score HIGH)"),
        ("https://paypal.com", "Real PayPal (should score LOW)"),
        ("https://google.com", "Real Google (should score LOW)"),
        ("https://premierpaymentprocessing.com/includes/boleto-2012.php", "Payment fraud"),
        ("https://randomsite.com/login/index.html", "Generic phishing pattern"),
        ("https://amazon-verify.tk", "Amazon phishing"),
    ]
    
    for url, description in test_cases:
        print(f"\n{'='*70}")
        print(f"Testing: {description}")
        print(f"URL: {url}")
        print('='*70)
        
        result = scanner.scan(url)
        
        print(f"\n📊 RESULT:")
        print(f"   Risk Score: {result['risk_score']}/100")
        if 'ml_contribution' in result['details']:
            print(f"   ML Contribution: +{result['details']['ml_contribution']} points")
        print(f"   Verdict: {result['verdict']}")
        print(f"   Risk Level: {result['risk_level'].upper()}")
        
        # Show ML-detected patterns
        ml_indicators = [
            ind for ind in result['indicators']['phishing'] + 
                          result['indicators']['warnings'] + 
                          result['indicators']['negative']
            if 'ML:' in ind
        ]
        
        if ml_indicators:
            print(f"\n🤖 ML Patterns Detected:")
            for ind in ml_indicators[:5]:  # Show top 5
                print(f"   • {ind}")
    
    print("\n" + "="*70)
    print("✅ TEST COMPLETE")
    print("="*70)
    print("\nThe enhanced scanner combines:")
    print("  • Traditional phishing detection rules")
    print("  • ML patterns learned from 156,422 real phishing URLs")
    print("  • Brand impersonation detection")
    print("  • Path analysis from actual scams")
    print("\n💡 Use this in your Flask app for better accuracy!")
