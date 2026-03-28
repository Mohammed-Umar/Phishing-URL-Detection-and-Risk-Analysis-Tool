import re
from urllib.parse import urlparse
import tldextract

class URLAnalyzer:
    """Extracts features from a URL for phishing detection."""

    def __init__(self, url):
        self.url = url.lower().strip()
        self.parsed_url = urlparse(self.url)
        self.extracted = tldextract.extract(self.url)
        self.domain = self.extracted.domain + "." + self.extracted.suffix

    def get_features(self):
        """Returns a dictionary of features."""
        features = {
            "url_length": len(self.url),
            "num_dots": self.url.count("."),
            "has_at_symbol": "@" in self.url,
            "has_double_slash": "//" in self.parsed_url.path,
            "has_dash": "-" in self.domain,
            "num_subdomains": len(self.extracted.subdomain.split(".")) if self.extracted.subdomain else 0,
            "is_ip_address": self._check_for_ip(),
            "has_https": self.parsed_url.scheme == "https",
            "path_depth": len([x for x in self.parsed_url.path.split("/") if x]),
            "query_length": len(self.parsed_url.query),
        }
        return features

    def _check_for_ip(self):
        """Checks if the domain is an IP address (v4 or v6)."""
        ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        domain = self.extracted.domain
        if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
            return True
        return False
