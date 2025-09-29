"""
AppSec collector for HTTP/TLS checks, SBOM, DAST, and policy validation
"""

import ssl
import socket
import subprocess
import json
import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from agent.collectors.base import BaseCollector
from agent.appsec.http_checker import HTTPChecker
from agent.appsec.sbom_generator import SBOMGenerator
from agent.appsec.dast_scanner import DASTScanner
from agent.appsec.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)

class AppSecCollector(BaseCollector):
    """Collects Application Security information"""
    
    def __init__(self, timeout: int = 60):
        super().__init__(timeout)
        self.http_checker = HTTPChecker()
        self.sbom_generator = SBOMGenerator()
        self.dast_scanner = DASTScanner()
        self.policy_engine = PolicyEngine()
        
        # Default targets for scanning
        self.default_targets = [
            "https://localhost",
            "http://localhost",
            "https://127.0.0.1",
            "http://127.0.0.1"
        ]
    
    def collect(self) -> Dict[str, Any]:
        """Collect all AppSec information"""
        return {
            "http_checks": self._collect_http_checks(),
            "sbom": self._collect_sbom(),
            "dast": self._collect_dast(),
            "policies": self._collect_policy_results()
        }
    
    def _collect_http_checks(self) -> List[Dict[str, Any]]:
        """Collect HTTP security checks"""
        checks = []
        
        # Find HTTP services from network scan
        http_services = self._find_http_services()
        
        # Add default targets
        all_targets = list(set(self.default_targets + http_services))
        
        for target in all_targets:
            try:
                check_result = self.http_checker.check_target(target)
                if check_result:
                    checks.append(check_result)
            except Exception as e:
                logger.error(f"Failed to check {target}: {e}")
        
        return checks
    
    def _find_http_services(self) -> List[str]:
        """Find HTTP services from network ports"""
        http_services = []
        
        try:
            # Get open ports using ss
            result = self.run_command(["ss", "-tlnp"], timeout=10)
            
            for line in result.stdout.split('\n')[1:]:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                # Parse local address
                local_addr = parts[3]
                if ':' not in local_addr:
                    continue
                
                addr, port = local_addr.rsplit(':', 1)
                port_num = self.parse_int(port)
                
                # Check if this is an HTTP service
                if port_num == 80:
                    http_services.append(f"http://{addr}:{port}")
                elif port_num == 443:
                    http_services.append(f"https://{addr}:{port}")
                elif port_num in [8080, 8443, 8000, 9000]:
                    # Common alternative HTTP ports
                    protocol = "https" if port_num in [443, 8443] else "http"
                    http_services.append(f"{protocol}://{addr}:{port}")
        
        except Exception as e:
            logger.error(f"Failed to find HTTP services: {e}")
        
        return http_services
    
    def _collect_sbom(self) -> Dict[str, Any]:
        """Collect Software Bill of Materials"""
        try:
            return self.sbom_generator.generate_sbom()
        except Exception as e:
            logger.error(f"Failed to generate SBOM: {e}")
            return {
                "format": "CycloneDX",
                "components": []
            }
    
    def _collect_dast(self) -> Dict[str, Any]:
        """Collect DAST scan results"""
        try:
            # Find web applications to scan
            web_targets = self._find_web_targets()
            
            if web_targets:
                return self.dast_scanner.scan_targets(web_targets)
            else:
                return {
                    "tool": "zap",
                    "issues": []
                }
        except Exception as e:
            logger.error(f"Failed to run DAST scan: {e}")
            return {
                "tool": "zap", 
                "issues": []
            }
    
    def _find_web_targets(self) -> List[str]:
        """Find web application targets for DAST scanning"""
        targets = []
        
        try:
            # Look for common web servers
            result = self.run_command(["ps", "aux"], timeout=10)
            
            web_processes = ["nginx", "apache2", "httpd", "tomcat", "node", "python", "php"]
            
            for line in result.stdout.split('\n'):
                for process in web_processes:
                    if process in line.lower():
                        # Extract URL from process (simplified)
                        if "localhost" in line or "127.0.0.1" in line:
                            targets.append("http://localhost")
                            targets.append("https://localhost")
                        break
        
        except Exception as e:
            logger.error(f"Failed to find web targets: {e}")
        
        return list(set(targets))  # Remove duplicates
    
    def _collect_policy_results(self) -> List[Dict[str, Any]]:
        """Collect policy validation results"""
        try:
            return self.policy_engine.evaluate_policies()
        except Exception as e:
            logger.error(f"Failed to evaluate policies: {e}")
            return []
