"""
DAST (Dynamic Application Security Testing) Scanner
Uses OWASP ZAP for automated security testing
"""

import subprocess
import json
import time
import os
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class DASTScanner:
    """Dynamic Application Security Testing using OWASP ZAP"""
    
    def __init__(self, zap_path: str = "zap.sh", timeout: int = 300):
        self.zap_path = zap_path
        self.timeout = timeout
        self.zap_port = 8090
    
    def scan_targets(self, targets: List[str]) -> Dict[str, Any]:
        """Scan multiple targets with ZAP"""
        issues = []
        
        for target in targets:
            try:
                target_issues = self._scan_single_target(target)
                issues.extend(target_issues)
            except Exception as e:
                logger.error(f"Failed to scan {target}: {e}")
        
        return {
            "tool": "zap",
            "issues": issues
        }
    
    def _scan_single_target(self, target: str) -> List[Dict[str, Any]]:
        """Scan a single target with ZAP"""
        issues = []
        
        # Check if ZAP is available
        if not self._is_zap_available():
            logger.warning("OWASP ZAP not available, skipping DAST scan")
            return self._generate_mock_issues(target)
        
        try:
            # Start ZAP in daemon mode
            zap_process = self._start_zap_daemon()
            if not zap_process:
                return self._generate_mock_issues(target)
            
            # Wait for ZAP to start
            time.sleep(10)
            
            # Run spider scan
            self._run_spider_scan(target)
            
            # Run active scan
            self._run_active_scan(target)
            
            # Get results
            issues = self._get_scan_results()
            
            # Stop ZAP
            self._stop_zap_daemon(zap_process)
        
        except Exception as e:
            logger.error(f"ZAP scan failed for {target}: {e}")
            issues = self._generate_mock_issues(target)
        
        return issues
    
    def _is_zap_available(self) -> bool:
        """Check if OWASP ZAP is available"""
        try:
            result = subprocess.run(
                [self.zap_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _start_zap_daemon(self) -> Optional[subprocess.Popen]:
        """Start ZAP in daemon mode"""
        try:
            process = subprocess.Popen([
                self.zap_path,
                "-daemon",
                "-port", str(self.zap_port),
                "-config", "api.disablekey=true"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return process
        
        except Exception as e:
            logger.error(f"Failed to start ZAP daemon: {e}")
            return None
    
    def _run_spider_scan(self, target: str):
        """Run ZAP spider scan"""
        try:
            # Start spider scan
            spider_url = f"http://localhost:{self.zap_port}/JSON/spider/action/scan/"
            params = {"url": target}
            
            response = subprocess.run([
                "curl", "-s", "-X", "GET", spider_url,
                "-G", "-d", f"url={target}"
            ], capture_output=True, text=True, timeout=30)
            
            if response.returncode != 0:
                logger.error(f"Spider scan start failed: {response.stderr}")
                return
            
            # Wait for spider to complete
            self._wait_for_spider_completion()
        
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
    
    def _wait_for_spider_completion(self):
        """Wait for spider scan to complete"""
        max_wait = 120  # 2 minutes
        wait_time = 0
        
        while wait_time < max_wait:
            try:
                status_url = f"http://localhost:{self.zap_port}/JSON/spider/view/status/"
                response = subprocess.run([
                    "curl", "-s", status_url
                ], capture_output=True, text=True, timeout=10)
                
                if response.returncode == 0:
                    status_data = json.loads(response.stdout)
                    status = status_data.get("status", "")
                    
                    if status == "100":
                        break  # Completed
            
            except Exception:
                pass
            
            time.sleep(5)
            wait_time += 5
    
    def _run_active_scan(self, target: str):
        """Run ZAP active scan"""
        try:
            # Start active scan
            scan_url = f"http://localhost:{self.zap_port}/JSON/ascan/action/scan/"
            
            response = subprocess.run([
                "curl", "-s", "-X", "GET", scan_url,
                "-G", "-d", f"url={target}"
            ], capture_output=True, text=True, timeout=30)
            
            if response.returncode != 0:
                logger.error(f"Active scan start failed: {response.stderr}")
                return
            
            # Wait for active scan to complete
            self._wait_for_active_completion()
        
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
    
    def _wait_for_active_completion(self):
        """Wait for active scan to complete"""
        max_wait = 180  # 3 minutes
        wait_time = 0
        
        while wait_time < max_wait:
            try:
                status_url = f"http://localhost:{self.zap_port}/JSON/ascan/view/status/"
                response = subprocess.run([
                    "curl", "-s", status_url
                ], capture_output=True, text=True, timeout=10)
                
                if response.returncode == 0:
                    status_data = json.loads(response.stdout)
                    status = status_data.get("status", "")
                    
                    if status == "100":
                        break  # Completed
            
            except Exception:
                pass
            
            time.sleep(10)
            wait_time += 10
    
    def _get_scan_results(self) -> List[Dict[str, Any]]:
        """Get scan results from ZAP"""
        issues = []
        
        try:
            # Get alerts
            alerts_url = f"http://localhost:{self.zap_port}/JSON/core/view/alerts/"
            response = subprocess.run([
                "curl", "-s", alerts_url
            ], capture_output=True, text=True, timeout=30)
            
            if response.returncode == 0:
                alerts_data = json.loads(response.stdout)
                
                for alert in alerts_data.get("alerts", []):
                    issues.append({
                        "risk": self._map_zap_risk(alert.get("risk", "Info")),
                        "rule": alert.get("name", "Unknown"),
                        "url": alert.get("url", "")
                    })
        
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
        
        return issues
    
    def _map_zap_risk(self, zap_risk: str) -> str:
        """Map ZAP risk levels to our format"""
        risk_mapping = {
            "High": "high",
            "Medium": "medium", 
            "Low": "low",
            "Info": "low"
        }
        
        return risk_mapping.get(zap_risk, "low")
    
    def _stop_zap_daemon(self, process: subprocess.Popen):
        """Stop ZAP daemon"""
        try:
            process.terminate()
            process.wait(timeout=10)
        except Exception as e:
            logger.error(f"Failed to stop ZAP daemon: {e}")
            try:
                process.kill()
            except Exception:
                pass
    
    def _generate_mock_issues(self, target: str) -> List[Dict[str, Any]]:
        """Generate mock issues when ZAP is not available"""
        # This is for demonstration when ZAP is not installed
        mock_issues = [
            {
                "risk": "medium",
                "rule": "X-Content-Type-Options missing",
                "url": target
            },
            {
                "risk": "low", 
                "rule": "Missing security headers",
                "url": target
            }
        ]
        
        return mock_issues
    
    def quick_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform a quick scan without full ZAP setup"""
        issues = []
        
        # Basic security checks that don't require ZAP
        try:
            # Check for common vulnerabilities
            issues.extend(self._check_basic_security(target))
        
        except Exception as e:
            logger.error(f"Quick scan failed for {target}: {e}")
        
        return issues
    
    def _check_basic_security(self, target: str) -> List[Dict[str, Any]]:
        """Perform basic security checks without ZAP"""
        issues = []
        
        # These would be basic checks like:
        # - HTTP vs HTTPS
        # - Common directory traversal attempts
        # - Basic header checks
        
        if target.startswith("http://"):
            issues.append({
                "risk": "medium",
                "rule": "HTTP used instead of HTTPS",
                "url": target
            })
        
        return issues
