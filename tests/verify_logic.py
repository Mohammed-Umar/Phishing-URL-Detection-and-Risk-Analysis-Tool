import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.analyzer import URLAnalyzer
from engine.detector import URLDetector
from engine.typosquatting import TyposquattingDetector

def test_url(url):
    print(f"\nAnalyzing: {url}")
    analyzer = URLAnalyzer(url)
    features = analyzer.get_features()
    
    detector = URLDetector(features, url)
    result = detector.detect()
    
    typo_detector = TyposquattingDetector(analyzer.domain)
    suggestion = typo_detector.check()
    
    print(f"Level: {result['level']} (Score: {result['score']})")
    print(f"Reasons: {', '.join(result['reasons'])}")
    if suggestion:
        print(f"Suggestion: This looks like a spoof of {suggestion['brand']} ({suggestion['domain']})")
    print("-" * 30)

if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "https://secure-bank-verify-login.account-update.com/paypal",
        "http://goggle.com/signin",
        "https://paypal.com@phish-site.net/secure",
        "https://faceb0ok.com/login",
        "https://pyapal.com/verify",
        "https://g0ogle.co"
    ]
    
    for url in test_urls:
        test_url(url)
