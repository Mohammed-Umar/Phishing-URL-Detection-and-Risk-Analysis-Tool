import difflib

class TyposquattingDetector:
    """Detects domain typosquatting."""

    # Top popular domains (sample list)
    TOP_DOMAINS = [
        "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", 
        "netflix.com", "paypal.com", "github.com", "twitter.com", "instagram.com", 
        "linkedin.com", "youtube.com", "gmail.com", "yahoo.com", "bing.com", 
        "outlook.com", "zoom.us", "ebay.com", "walmart.com", "dropbox.com",
        "adobe.com", "slack.com", "spotify.com", "whatsapp.com", "tiktok.com"
    ]

    def __init__(self, domain):
        self.domain = domain.lower()

    def check(self):
        """Checks for similarity against top domains."""
        if self.domain in self.TOP_DOMAINS:
            return None  # It IS a top domain

        for legit_domain in self.TOP_DOMAINS:
            similarity = difflib.SequenceMatcher(None, self.domain, legit_domain).ratio()
            if 0.8 <= similarity < 1.0:
                return legit_domain
        
        return None
