class URLDetector:
    """Calculates phishing risk score from features."""

    # Risk Weights
    WEIGHTS = {
        "url_length": 10,
        "num_dots": 5,
        "has_at_symbol": 20,
        "is_ip_address": 35,
        "has_double_slash": 15,
        "num_subdomains": 10,
        "no_https": 10,
        "keywords": 30,
    }

    # Suspicious Keywords
    SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "bank", "account", "update", "signin", "paypal", "signin", "payment", "invoice"]

    def __init__(self, features, raw_url):
        self.features = features
        self.url = raw_url.lower()

    def detect(self):
        """Calculates score and risk level."""
        score = 0
        reasons = []

        if self.features["url_length"] > 75:
            score += self.WEIGHTS["url_length"]
            reasons.append("Long URL (>75 characters)")
        
        if self.features["num_dots"] > 3:
            score += self.WEIGHTS["num_dots"]
            reasons.append(f"High number of dots ({self.features['num_dots']})")

        if self.features["has_at_symbol"]:
            score += self.WEIGHTS["has_at_symbol"]
            reasons.append("Contains '@' symbol (often masks true domain)")

        if self.features["is_ip_address"]:
            score += self.WEIGHTS["is_ip_address"]
            reasons.append("Uses IP address instead of domain name")

        if self.features["has_double_slash"]:
            score += self.WEIGHTS["has_double_slash"]
            reasons.append("Contains '//' in path (potential redirect)")

        if self.features["num_subdomains"] > 3:
            score += self.WEIGHTS["num_subdomains"]
            reasons.append(f"Excessive subdomains ({self.features['num_subdomains']})")

        if not self.features["has_https"]:
            score += self.WEIGHTS["no_https"]
            reasons.append("Does not use HTTPS")

        # Keyword checking
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in self.url]
        if found_keywords:
            score += self.WEIGHTS["keywords"]
            reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")

        # Max score is 100
        score = min(score, 100)

        # Classification
        if score <= 30:
            level = "Safe"
            color = "#2ECC71"  # Good Green
        elif score <= 70:
            level = "Suspicious"
            color = "#F1C40F"  # WARNING Yellow
        else:
            level = "Dangerous"
            color = "#E74C3C"  # DANGER Red

        return {
            "score": score,
            "level": level,
            "color": color,
            "reasons": reasons
        }
