import difflib

class TyposquattingDetector:
    """Detects domain typosquatting."""

    # Top popular domains mapping with brand names
    TOP_DOMAINS = {
        "google.com": "Google",
        "facebook.com": "Facebook",
        "amazon.com": "Amazon",
        "apple.com": "Apple",
        "microsoft.com": "Microsoft",
        "netflix.com": "Netflix",
        "paypal.com": "PayPal",
        "github.com": "GitHub",
        "twitter.com": "Twitter",
        "instagram.com": "Instagram",
        "linkedin.com": "LinkedIn",
        "youtube.com": "YouTube",
        "gmail.com": "Gmail",
        "yahoo.com": "Yahoo",
        "bing.com": "Bing",
        "outlook.com": "Outlook",
        "zoom.us": "Zoom",
        "ebay.com": "eBay",
        "walmart.com": "Walmart",
        "dropbox.com": "Dropbox",
        "adobe.com": "Adobe",
        "slack.com": "Slack",
        "spotify.com": "Spotify",
        "whatsapp.com": "WhatsApp",
        "tiktok.com": "TikTok"
    }

    def __init__(self, domain):
        self.domain = domain.lower()

    def check(self):
        """Checks for similarity against top domains. Returns (legit_domain, brand_name) or None."""
        if self.domain in self.TOP_DOMAINS:
            return None  # It IS a top domain

        for legit_domain, brand_name in self.TOP_DOMAINS.items():
            # Basic similarity check
            similarity = difflib.SequenceMatcher(None, self.domain, legit_domain).ratio()
            if 0.8 <= similarity < 1.0:
                return {"domain": legit_domain, "brand": brand_name}
        
        return None
