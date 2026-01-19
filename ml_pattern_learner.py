"""
Unsupervised Phishing Pattern Learner
Learns ONLY from phishing URLs (no legitimate comparison needed)
Finds common patterns that appear frequently in scams
"""

import pandas as pd
import re
import json
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, List

class UnsupervisedPhishingLearner:
    """
    Learn patterns from ONLY phishing URLs
    No legitimate comparison needed
    """
    
    def analyze_phishing_only(self, csv_path: str):
        print("📊 Loading phishing dataset...")
        
        try:
            df = pd.read_csv(csv_path)
            print(f"✅ Loaded {len(df)} URLs")
            
            # Use ONLY the 'bad' labeled URLs (actual phishing)
            phishing_urls = df[df['Label'] == 'bad']['URL'].tolist()
            
            print(f"\n🚨 Analyzing {len(phishing_urls)} CONFIRMED phishing URLs")
            print("   (Ignoring 'good' labels - they appear corrupted)")
            
            # Extract all patterns
            print("\n🔍 Extracting common phishing patterns...")
            patterns = self._extract_all_patterns(phishing_urls)
            
            # Generate rules based on frequency
            print("\n⚙️  Generating detection rules...")
            rules = self._generate_frequency_rules(patterns, len(phishing_urls))
            
            # Save
            self._save_rules(rules)
            self._print_summary(rules)
            
            return rules
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _extract_all_patterns(self, urls: List[str]) -> Dict:
        """Extract ALL patterns from phishing URLs"""
        patterns = {
            'tlds': Counter(),
            'keywords': Counter(),
            'path_keywords': Counter(),
            'suspicious_chars': Counter(),
            'domain_lengths': [],
            'url_lengths': [],
            'subdomain_counts': Counter(),
            'has_ip': 0,
            'has_at': 0,
            'has_hyphen': 0,
            'has_numbers': 0,
            'brand_mentions': Counter(),
        }
        
        # Common brand names to detect
        brands = ['paypal', 'amazon', 'apple', 'google', 'facebook', 'microsoft',
                 'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'bank',
                 'chase', 'wellsfargo', 'citi', 'secure', 'verify', 'account']
        
        for url in urls:
            try:
                url_str = str(url).lower()
                parsed = urlparse(url_str)
                domain = parsed.hostname or ''
                path = parsed.path or ''
                
                # TLD
                if '.' in domain:
                    tld = '.' + domain.split('.')[-1]
                    patterns['tlds'][tld] += 1
                
                # Domain keywords
                domain_words = re.findall(r'[a-z]{4,}', domain)
                for word in domain_words:
                    patterns['keywords'][word] += 1
                
                # Path keywords  
                path_words = re.findall(r'[a-z]{4,}', path)
                for word in path_words:
                    patterns['path_keywords'][word] += 1
                
                # Brand mentions
                for brand in brands:
                    if brand in url_str:
                        patterns['brand_mentions'][brand] += 1
                
                # Suspicious characters
                if '-' in domain:
                    patterns['has_hyphen'] += 1
                    patterns['suspicious_chars']['hyphen'] += 1
                
                if '@' in url_str:
                    patterns['has_at'] += 1
                    patterns['suspicious_chars']['at_symbol'] += 1
                
                # IP address
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    patterns['has_ip'] += 1
                    patterns['suspicious_chars']['ip_address'] += 1
                
                # Numbers in domain
                if any(c.isdigit() for c in domain):
                    patterns['has_numbers'] += 1
                
                # Subdomain count
                subdomain_count = domain.count('.')
                patterns['subdomain_counts'][subdomain_count] += 1
                
                # Lengths
                patterns['domain_lengths'].append(len(domain))
                patterns['url_lengths'].append(len(url_str))
                
            except Exception:
                continue
        
        return patterns
    
    def _generate_frequency_rules(self, patterns: Dict, total_urls: int) -> Dict:
        """
        Generate rules based on frequency in phishing URLs
        If something appears in >5% of phishing, it's a pattern
        """
        rules = {
            'high_risk_tlds': [],
            'phishing_keywords': [],
            'path_indicators': [],
            'brand_impersonation': [],
            'structural_indicators': []
        }
        
        # TLDs that appear frequently in phishing
        print("\n📊 TLD Analysis:")
        for tld, count in patterns['tlds'].most_common(50):
            frequency = count / total_urls
            
            # If appears in >0.5% of phishing URLs, it's suspicious
            if frequency > 0.005 and count > 10:
                score = min(30, int(frequency * 1000))
                rules['high_risk_tlds'].append({
                    'tld': tld,
                    'score': score,
                    'frequency': round(frequency * 100, 2),
                    'count': count
                })
                print(f"   {tld:12} appears in {frequency*100:.2f}% of phishing ({count} times)")
        
        # Keywords that appear frequently in domains
        print("\n📊 Domain Keyword Analysis:")
        for keyword, count in patterns['keywords'].most_common(100):
            frequency = count / total_urls
            
            # If appears in >1% of phishing, it's a pattern
            if frequency > 0.01 and count > 20:
                score = min(25, int(frequency * 500))
                rules['phishing_keywords'].append({
                    'keyword': keyword,
                    'score': score,
                    'frequency': round(frequency * 100, 2),
                    'count': count
                })
                if len(rules['phishing_keywords']) <= 20:
                    print(f"   {keyword:15} appears in {frequency*100:.2f}% of phishing ({count} times)")
        
        # Path keywords (appear in URL paths)
        for keyword, count in patterns['path_keywords'].most_common(50):
            frequency = count / total_urls
            
            if frequency > 0.01 and count > 20:
                score = min(20, int(frequency * 400))
                rules['path_indicators'].append({
                    'keyword': keyword,
                    'score': score,
                    'frequency': round(frequency * 100, 2),
                    'count': count
                })
        
        # Brand impersonation
        print("\n📊 Brand Impersonation:")
        for brand, count in patterns['brand_mentions'].most_common(20):
            frequency = count / total_urls
            
            if count > 10:
                score = min(30, int(frequency * 600))
                rules['brand_impersonation'].append({
                    'brand': brand,
                    'score': score,
                    'frequency': round(frequency * 100, 2),
                    'count': count
                })
                print(f"   {brand:15} appears in {frequency*100:.2f}% of phishing ({count} times)")
        
        # Structural indicators
        print("\n📊 Structural Patterns:")
        
        # IP addresses
        ip_freq = patterns['has_ip'] / total_urls
        if ip_freq > 0.001:
            rules['structural_indicators'].append({
                'type': 'ip_address',
                'score': 30,
                'frequency': round(ip_freq * 100, 2)
            })
            print(f"   IP addresses: {ip_freq*100:.2f}% of phishing")
        
        # @ symbol
        at_freq = patterns['has_at'] / total_urls
        if at_freq > 0.001:
            rules['structural_indicators'].append({
                'type': 'at_symbol',
                'score': 35,
                'frequency': round(at_freq * 100, 2)
            })
            print(f"   @ symbol: {at_freq*100:.2f}% of phishing")
        
        # Hyphens
        hyphen_freq = patterns['has_hyphen'] / total_urls
        if hyphen_freq > 0.05:
            rules['structural_indicators'].append({
                'type': 'hyphen',
                'score': 10,
                'frequency': round(hyphen_freq * 100, 2)
            })
            print(f"   Hyphens: {hyphen_freq*100:.2f}% of phishing")
        
        return rules
    
    def _save_rules(self, rules: Dict):
        with open('learned_patterns.json', 'w') as f:
            json.dump(rules, f, indent=2)
        print("\n💾 Saved to: learned_patterns.json")
    
    def _print_summary(self, rules: Dict):
        print("\n" + "="*70)
        print("LEARNED PHISHING PATTERNS (from actual phishing URLs)")
        print("="*70)
        
        print(f"\n✅ Generated:")
        print(f"   • {len(rules['high_risk_tlds'])} high-risk TLDs")
        print(f"   • {len(rules['phishing_keywords'])} domain keywords")
        print(f"   • {len(rules['path_indicators'])} path indicators")
        print(f"   • {len(rules['brand_impersonation'])} brand mentions")
        print(f"   • {len(rules['structural_indicators'])} structural patterns")
        
        print("\n" + "="*70)
        print("TOP PHISHING TLDs (most common in scams):")
        print("="*70)
        for rule in rules['high_risk_tlds'][:15]:
            print(f"   {rule['tld']:12} +{rule['score']:2} pts  "
                  f"(appears in {rule['frequency']:.2f}% of phishing)")
        
        print("\n" + "="*70)
        print("TOP PHISHING KEYWORDS (most common in scam domains):")
        print("="*70)
        for rule in rules['phishing_keywords'][:20]:
            print(f"   {rule['keyword']:15} +{rule['score']:2} pts  "
                  f"(appears in {rule['frequency']:.2f}% of phishing)")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║     UNSUPERVISED PHISHING PATTERN LEARNER                        ║
║  Learns from ACTUAL phishing URLs (no comparison needed)         ║
╚══════════════════════════════════════════════════════════════════╝

Since the 'good' URLs in the dataset are corrupted/garbage,
we'll learn patterns from ONLY the confirmed phishing URLs ('bad').

This finds what's COMMON in phishing attempts.
""")
    
    csv_file = input("\nEnter CSV file path (or press Enter for 'phishing_urls.csv'): ").strip()
    if not csv_file:
        csv_file = 'phishing_urls.csv'
    
    print("\n" + "="*70)
    print("ANALYZING PHISHING PATTERNS")
    print("="*70)
    
    learner = UnsupervisedPhishingLearner()
    rules = learner.analyze_phishing_only(csv_file)
    
    if rules:
        print("\n" + "="*70)
        print("✅ LEARNING COMPLETE!")
        print("="*70)
        print("\nYour scanner now knows:")
        print("  • Which TLDs scammers use most")
        print("  • Which keywords appear in phishing domains")
        print("  • Which brands scammers impersonate")
        print("  • Common structural patterns in scam URLs")
        print("\n💡 Use these patterns in your scanner!")
    else:
        print("\n❌ Learning failed.")
