"""
Software Bill of Materials (SBOM) Generator
Generates CycloneDX format SBOM and enriches with CVE data
"""

import json
import subprocess
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SBOMGenerator:
    """Generates SBOM for system packages and applications"""
    
    def __init__(self):
        self.cve_db = {}  # Simple CVE database (in real implementation, use proper CVE DB)
        self._load_cve_database()
    
    def generate_sbom(self) -> Dict[str, Any]:
        """Generate complete SBOM with CVE enrichment"""
        components = []
        
        # Collect system packages
        system_packages = self._collect_system_packages()
        components.extend(system_packages)
        
        # Collect Python packages
        python_packages = self._collect_python_packages()
        components.extend(python_packages)
        
        # Collect Node.js packages
        node_packages = self._collect_node_packages()
        components.extend(node_packages)
        
        # Enrich with CVE data
        for component in components:
            component["cves"] = self._get_cves_for_component(component["name"], component["version"])
        
        return {
            "format": "CycloneDX",
            "components": components
        }
    
    def _collect_system_packages(self) -> List[Dict[str, str]]:
        """Collect system packages (apt, yum, etc.)"""
        packages = []
        
        # Try APT (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ["dpkg", "-l"], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0:
                packages.extend(self._parse_dpkg_output(result.stdout))
        
        except Exception as e:
            logger.debug(f"Could not collect APT packages: {e}")
        
        # Try YUM (CentOS/RHEL)
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0:
                packages.extend(self._parse_rpm_output(result.stdout))
        
        except Exception as e:
            logger.debug(f"Could not collect RPM packages: {e}")
        
        return packages
    
    def _parse_dpkg_output(self, output: str) -> List[Dict[str, str]]:
        """Parse dpkg output"""
        packages = []
        
        for line in output.split('\n'):
            if line.startswith('ii'):  # Installed packages
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1]
                    version = parts[2]
                    
                    # Filter out common system packages for brevity
                    if self._is_interesting_package(name):
                        packages.append({
                            "name": name,
                            "version": version
                        })
        
        return packages
    
    def _parse_rpm_output(self, output: str) -> List[Dict[str, str]]:
        """Parse rpm output"""
        packages = []
        
        for line in output.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    
                    if self._is_interesting_package(name):
                        packages.append({
                            "name": name,
                            "version": version
                        })
        
        return packages
    
    def _is_interesting_package(self, name: str) -> bool:
        """Filter packages to only include interesting ones"""
        # Common security-relevant packages
        interesting_prefixes = [
            "openssl", "libssl", "curl", "wget", "ssh", "openssh", 
            "nginx", "apache", "httpd", "mysql", "postgresql",
            "python", "node", "npm", "java", "tomcat", "docker"
        ]
        
        return any(name.lower().startswith(prefix) for prefix in interesting_prefixes)
    
    def _collect_python_packages(self) -> List[Dict[str, str]]:
        """Collect Python packages"""
        packages = []
        
        try:
            # Try pip list
            result = subprocess.run(
                ["pip", "list", "--format=json"], 
                capture_output=True, 
                text=True, 
                timeout=20
            )
            
            if result.returncode == 0:
                pip_packages = json.loads(result.stdout)
                for pkg in pip_packages:
                    packages.append({
                        "name": pkg["name"],
                        "version": pkg["version"]
                    })
        
        except Exception as e:
            logger.debug(f"Could not collect Python packages: {e}")
        
        return packages
    
    def _collect_node_packages(self) -> List[Dict[str, str]]:
        """Collect Node.js packages"""
        packages = []
        
        try:
            # Check for package.json
            result = subprocess.run(
                ["npm", "list", "--json", "--depth=0"], 
                capture_output=True, 
                text=True, 
                timeout=20
            )
            
            if result.returncode == 0:
                npm_data = json.loads(result.stdout)
                if "dependencies" in npm_data:
                    for name, info in npm_data["dependencies"].items():
                        if isinstance(info, dict) and "version" in info:
                            packages.append({
                                "name": name,
                                "version": info["version"]
                            })
        
        except Exception as e:
            logger.debug(f"Could not collect Node.js packages: {e}")
        
        return packages
    
    def _load_cve_database(self):
        """Load CVE database (simplified implementation)"""
        # In a real implementation, this would load from a proper CVE database
        # For demo purposes, we'll use a small hardcoded database
        self.cve_db = {
            "openssl": {
                "1.1.1": ["CVE-2023-0286", "CVE-2022-0778"],
                "1.0.2": ["CVE-2019-1547", "CVE-2019-1551"]
            },
            "curl": {
                "7.68.0": ["CVE-2020-8169"],
                "7.64.0": ["CVE-2019-5481", "CVE-2019-5482"]
            },
            "nginx": {
                "1.18.0": ["CVE-2021-23017"],
                "1.16.0": ["CVE-2019-20372"]
            }
        }
    
    def _get_cves_for_component(self, name: str, version: str) -> List[str]:
        """Get CVEs for a specific component version"""
        name_lower = name.lower()
        
        # Check exact match
        if name_lower in self.cve_db:
            version_major = self._get_version_major(version)
            if version_major in self.cve_db[name_lower]:
                return self.cve_db[name_lower][version_major]
        
        # Check partial matches
        for package_name, versions in self.cve_db.items():
            if package_name in name_lower:
                version_major = self._get_version_major(version)
                if version_major in versions:
                    return versions[version_major]
        
        return []
    
    def _get_version_major(self, version: str) -> str:
        """Extract major version from version string"""
        # Extract major.minor from version (e.g., "1.1.1w" -> "1.1.1")
        match = re.match(r'^(\d+\.\d+\.\d+)', version)
        if match:
            return match.group(1)
        
        # Fallback to first two parts
        match = re.match(r'^(\d+\.\d+)', version)
        if match:
            return match.group(1)
        
        return version
    
    def export_cyclonedx(self, output_file: str):
        """Export SBOM in CycloneDX format"""
        sbom_data = self.generate_sbom()
        
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "Security Monitor",
                        "name": "SBOM Generator",
                        "version": "1.0.0"
                    }
                ]
            },
            "components": []
        }
        
        # Convert to CycloneDX format
        for component in sbom_data["components"]:
            cyclonedx["components"].append({
                "type": "library",
                "name": component["name"],
                "version": component["version"],
                "vulnerabilities": [
                    {
                        "id": cve,
                        "ratings": [
                            {
                                "method": "other",
                                "severity": "unknown"
                            }
                        ]
                    }
                    for cve in component["cves"]
                ]
            })
        
        with open(output_file, 'w') as f:
            json.dump(cyclonedx, f, indent=2)
        
        logger.info(f"CycloneDX SBOM exported to {output_file}")
