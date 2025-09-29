"""
HTTP Security Checker for headers, TLS, cookies, etc.
"""

import ssl
import socket
import urllib.request
import urllib.parse
import logging
from typing import Dict, Any, Optional, List
from urllib.error import URLError, HTTPError
import re

logger = logging.getLogger(__name__)

class HTTPChecker:
    """Checks HTTP security headers and TLS configuration"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
        # Security headers to check
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy", 
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "X-XSS-Protection",
            "Permissions-Policy"
        ]
        
        # Cookie security attributes
        self.cookie_security_attrs = ["Secure", "HttpOnly", "SameSite"]
    
    def check_target(self, url: str) -> Optional[Dict[str, Any]]:
        """Check security configuration for a target URL"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            
            if parsed_url.scheme == "https":
                return self._check_https_target(url)
            else:
                return self._check_http_target(url)
        
        except Exception as e:
            logger.error(f"Failed to check {url}: {e}")
            return None
    
    def _check_https_target(self, url: str) -> Dict[str, Any]:
        """Check HTTPS target with TLS and headers"""
        findings = []
        
        # Check TLS configuration
        tls_info = self._check_tls_config(url)
        
        # Check HTTP headers
        headers = self._get_http_headers(url)
        header_checks = self._check_security_headers(headers)
        findings.extend(header_checks["findings"])
        
        # Check cookies
        cookie_checks = self._check_cookie_security(headers.get("Set-Cookie", ""))
        findings.extend(cookie_checks)
        
        return {
            "target": url,
            "hsts": "Strict-Transport-Security" in headers,
            "tls_version": tls_info.get("version", "unknown"),
            "csp": "present" if headers.get("Content-Security-Policy") else "missing",
            "cookies_secure": cookie_checks.count("Secure cookie missing") == 0,
            "findings": findings
        }
    
    def _check_http_target(self, url: str) -> Dict[str, Any]:
        """Check HTTP target (should be flagged as insecure)"""
        findings = ["HTTP used instead of HTTPS"]
        
        headers = self._get_http_headers(url)
        header_checks = self._check_security_headers(headers)
        findings.extend(header_checks["findings"])
        
        return {
            "target": url,
            "hsts": False,
            "tls_version": "none",
            "csp": "present" if headers.get("Content-Security-Policy") else "missing",
            "cookies_secure": False,
            "findings": findings
        }
    
    def _check_tls_config(self, url: str) -> Dict[str, str]:
        """Check TLS configuration"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    return {
                        "version": tls_version,
                        "cipher": cipher[0] if cipher else "unknown",
                        "key_size": str(cipher[2]) if cipher else "unknown"
                    }
        
        except Exception as e:
            logger.error(f"TLS check failed for {url}: {e}")
            return {"version": "error", "cipher": "unknown", "key_size": "unknown"}
    
    def _get_http_headers(self, url: str) -> Dict[str, str]:
        """Get HTTP headers from URL"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Security-Monitor/1.0')
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                headers = {}
                for header, value in response.headers.items():
                    headers[header] = value
                return headers
        
        except (URLError, HTTPError) as e:
            logger.error(f"Failed to get headers from {url}: {e}")
            return {}
    
    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check presence and configuration of security headers"""
        findings = []
        present_headers = []
        
        for header in self.security_headers:
            if header in headers:
                present_headers.append(header)
                
                # Check header configuration
                value = headers[header]
                
                if header == "Strict-Transport-Security":
                    if "max-age" not in value:
                        findings.append(f"HSTS missing max-age: {header}")
                    elif "includeSubDomains" not in value:
                        findings.append(f"HSTS missing includeSubDomains: {header}")
                
                elif header == "Content-Security-Policy":
                    if not value.strip():
                        findings.append(f"CSP header is empty: {header}")
                
                elif header == "X-Frame-Options":
                    if value.upper() not in ["DENY", "SAMEORIGIN"]:
                        findings.append(f"X-Frame-Options should be DENY or SAMEORIGIN: {value}")
            
            else:
                findings.append(f"Missing security header: {header}")
        
        return {
            "present_headers": present_headers,
            "findings": findings
        }
    
    def _check_cookie_security(self, set_cookie_header: str) -> List[str]:
        """Check cookie security attributes"""
        findings = []
        
        if not set_cookie_header:
            return findings
        
        # Parse cookies (simplified)
        cookies = set_cookie_header.split(',')
        
        for cookie in cookies:
            cookie = cookie.strip()
            
            # Check for security attributes
            has_secure = "Secure" in cookie
            has_httponly = "HttpOnly" in cookie
            has_samesite = "SameSite" in cookie
            
            if not has_secure:
                findings.append("Secure cookie missing")
            if not has_httponly:
                findings.append("HttpOnly cookie missing")
            if not has_samesite:
                findings.append("SameSite cookie missing")
        
        return findings
    
    def get_tls_cipher_suites(self, hostname: str, port: int = 443) -> List[str]:
        """Get supported TLS cipher suites"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.shared_ciphers()
        
        except Exception as e:
            logger.error(f"Failed to get cipher suites for {hostname}:{port}: {e}")
            return []
