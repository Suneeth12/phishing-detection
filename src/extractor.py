"""
Feature extraction engine parsing 30+ lexical, domain, and structural URL features.
"""
import re
from urllib.parse import urlparse
from typing import Dict, Any

SHORTENING_SERVICES = r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs)"

class URLLexicalExtractor:
    def extract(self, url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        # 1. IP address in URL
        has_ip = 1 if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", domain) else 0
        
        # 2. URL Length
        url_len = len(url)
        len_flag = 1 if url_len > 75 else (0 if url_len > 54 else -1)

        # 3. Shortening Service
        is_shortened = 1 if re.search(SHORTENING_SERVICES, domain, re.I) else 0

        # 4. Have @ symbol
        has_at = 1 if "@" in url else 0

        # 5. Double slash redirect
        has_double_slash = 1 if url.rfind("//") > 7 else 0

        # 6. Prefix/Suffix '-' in domain
        has_hyphen = 1 if "-" in domain else 0

        # 7. Subdomains count
        subdomains = domain.split(".")
        subdomain_count = len(subdomains) - 2 if len(subdomains) > 2 else 0

        # 8. HTTPS token in domain
        has_https_in_domain = 1 if "https" in domain.lower() else 0

        # 9. Suspicious TLDs
        suspicious_tld = 1 if any(domain.endswith(tld) for tld in [".xyz", ".top", ".club", ".work", ".info", ".buzz"]) else 0

        # 10. Non-standard port
        has_custom_port = 1 if ":" in domain else 0

        return {
            "has_ip": has_ip,
            "url_length": url_len,
            "url_length_flag": len_flag,
            "is_shortened": is_shortened,
            "has_at_symbol": has_at,
            "has_double_slash_redirect": has_double_slash,
            "has_hyphen_in_domain": has_hyphen,
            "subdomain_depth": subdomain_count,
            "https_token_in_domain": has_https_in_domain,
            "suspicious_tld": suspicious_tld,
            "has_custom_port": has_custom_port,
            "domain": domain,
            "scheme": parsed.scheme
        }
