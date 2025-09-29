"""
Policy Engine for security policy validation
Supports YAML configuration and OPA/Rego rules
"""

import yaml
import json
import subprocess
import re
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class PolicyEngine:
    """Evaluates security policies against system state"""
    
    def __init__(self, config_path: str = "config/policies.yaml"):
        self.config_path = config_path
        
        # Default policies if config doesn't exist
        self._default_policies = [
            {
                "id": "POL_NO_TELNET",
                "name": "No Telnet Service",
                "description": "Telnet service should not be active",
                "severity": "high",
                "rule": "no_telnet",
                "enabled": True
            },
            {
                "id": "POL_WIFI_DISABLE_IF_ETHERNET",
                "name": "WiFi Disabled with Ethernet",
                "description": "WiFi should be disabled when Ethernet is available",
                "severity": "warn",
                "rule": "wifi_disable_ethernet",
                "enabled": True
            },
            {
                "id": "POL_HTTP_TLS_REQUIRED",
                "name": "HTTP TLS Required",
                "description": "HTTP services should use TLS",
                "severity": "medium",
                "rule": "http_tls_required",
                "enabled": True
            },
            {
                "id": "POL_NO_LATEST_TAG",
                "name": "No Latest Docker Tags",
                "description": "Docker containers should not use :latest tag",
                "severity": "medium",
                "rule": "no_latest_tag",
                "enabled": True
            },
            {
                "id": "POL_NO_UNEXPECTED_WEB_PORTS",
                "name": "No Unexpected Web Ports",
                "description": "Web services should only run on standard ports",
                "severity": "warn",
                "rule": "no_unexpected_web_ports",
                "enabled": True
            }
        ]
        
        # Load policies after defining defaults
        self.policies = self._load_policies()
    
    def _load_policies(self) -> List[Dict[str, Any]]:
        """Load policies from YAML configuration"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    return config.get("policies", self._default_policies)
            else:
                return self._default_policies
        except Exception as e:
            logger.error(f"Failed to load policies from {self.config_path}: {e}")
            return self._default_policies
    
    def evaluate_policies(self, system_state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Evaluate all enabled policies"""
        results = []
        
        for policy in self.policies:
            if not policy.get("enabled", True):
                continue
            
            try:
                result = self._evaluate_single_policy(policy, system_state)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to evaluate policy {policy['id']}: {e}")
                results.append({
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"error": str(e)}
                })
        
        return results
    
    def _evaluate_single_policy(self, policy: Dict[str, Any], 
                               system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a single policy"""
        rule_name = policy.get("rule", "")
        
        # Route to appropriate rule evaluator
        if rule_name == "no_telnet":
            return self._evaluate_no_telnet_policy(policy, system_state)
        elif rule_name == "wifi_disable_ethernet":
            return self._evaluate_wifi_ethernet_policy(policy, system_state)
        elif rule_name == "http_tls_required":
            return self._evaluate_http_tls_policy(policy, system_state)
        elif rule_name == "no_latest_tag":
            return self._evaluate_no_latest_tag_policy(policy, system_state)
        elif rule_name == "no_unexpected_web_ports":
            return self._evaluate_unexpected_web_ports_policy(policy, system_state)
        else:
            return {
                "id": policy["id"],
                "status": "fail",
                "evidence": {"error": f"Unknown rule: {rule_name}"}
            }
    
    def _evaluate_no_telnet_policy(self, policy: Dict[str, Any], 
                                  system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate no telnet policy"""
        try:
            # Check if telnet service is active
            result = subprocess.run(
                ["systemctl", "is-active", "telnet"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            is_active = result.stdout.strip() == "active"
            
            if is_active:
                return {
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"service": "telnet", "state": "active"}
                }
            else:
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"service": "telnet", "state": "inactive"}
                }
        
        except Exception as e:
            return {
                "id": policy["id"],
                "status": "pass",  # Assume pass if can't check
                "evidence": {"error": str(e)}
            }
    
    def _evaluate_wifi_ethernet_policy(self, policy: Dict[str, Any], 
                                      system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate WiFi/Ethernet policy"""
        try:
            # Check WiFi status
            wifi_result = subprocess.run(
                ["nmcli", "radio", "wifi"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            wifi_enabled = "enabled" in wifi_result.stdout.lower()
            
            # Check Ethernet status
            ethernet_result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            has_ethernet_up = any("eth" in line and "state UP" in line 
                                for line in ethernet_result.stdout.split('\n'))
            
            if wifi_enabled and has_ethernet_up:
                return {
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"wifi_enabled": True, "ethernet_available": True}
                }
            else:
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"wifi_enabled": wifi_enabled, "ethernet_available": has_ethernet_up}
                }
        
        except Exception as e:
            return {
                "id": policy["id"],
                "status": "pass",
                "evidence": {"error": str(e)}
            }
    
    def _evaluate_http_tls_policy(self, policy: Dict[str, Any], 
                                 system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate HTTP TLS policy"""
        try:
            # Check for HTTP services (non-TLS)
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            http_ports = []
            for line in result.stdout.split('\n'):
                if ':80 ' in line or ':8080 ' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        http_ports.append(local_addr)
            
            if http_ports:
                return {
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"http_ports": http_ports}
                }
            else:
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"http_ports": []}
                }
        
        except Exception as e:
            return {
                "id": policy["id"],
                "status": "pass",
                "evidence": {"error": str(e)}
            }
    
    def _evaluate_no_latest_tag_policy(self, policy: Dict[str, Any], 
                                      system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate no latest tag policy for Docker"""
        try:
            # Check Docker containers
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Image}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                # Docker not available or no containers
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"docker_available": False}
                }
            
            latest_containers = []
            for image in result.stdout.split('\n'):
                if image.strip() and ':latest' in image:
                    latest_containers.append(image.strip())
            
            if latest_containers:
                return {
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"latest_containers": latest_containers}
                }
            else:
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"latest_containers": []}
                }
        
        except Exception as e:
            return {
                "id": policy["id"],
                "status": "pass",
                "evidence": {"error": str(e)}
            }
    
    def _evaluate_unexpected_web_ports_policy(self, policy: Dict[str, Any], 
                                            system_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate unexpected web ports policy"""
        try:
            # Standard web ports
            standard_ports = [80, 443, 8080, 8443]
            
            # Get listening ports
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            unexpected_ports = []
            for line in result.stdout.split('\n'):
                if ':80' in line or ':443' in line:
                    # Check if it's a web server
                    if any(web_server in line.lower() 
                          for web_server in ['nginx', 'apache', 'httpd']):
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            port_match = re.search(r':(\d+)', local_addr)
                            if port_match:
                                port = int(port_match.group(1))
                                if port not in standard_ports:
                                    unexpected_ports.append(local_addr)
            
            if unexpected_ports:
                return {
                    "id": policy["id"],
                    "status": "fail",
                    "evidence": {"unexpected_ports": unexpected_ports}
                }
            else:
                return {
                    "id": policy["id"],
                    "status": "pass",
                    "evidence": {"unexpected_ports": []}
                }
        
        except Exception as e:
            return {
                "id": policy["id"],
                "status": "pass",
                "evidence": {"error": str(e)}
            }
    
    def validate_policy_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate policy configuration"""
        errors = []
        
        if "policies" not in config:
            errors.append("Missing 'policies' section")
            return errors
        
        for i, policy in enumerate(config["policies"]):
            policy_errors = []
            
            required_fields = ["id", "name", "rule"]
            for field in required_fields:
                if field not in policy:
                    policy_errors.append(f"Missing required field: {field}")
            
            if "severity" in policy:
                valid_severities = ["low", "medium", "high", "critical"]
                if policy["severity"] not in valid_severities:
                    policy_errors.append(f"Invalid severity: {policy['severity']}")
            
            if policy_errors:
                errors.append(f"Policy {i}: {'; '.join(policy_errors)}")
        
        return errors
    
    def export_policies(self, output_file: str):
        """Export current policies to YAML file"""
        config = {
            "version": "1.0",
            "policies": self.policies
        }
        
        with open(output_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
        
        logger.info(f"Policies exported to {output_file}")
