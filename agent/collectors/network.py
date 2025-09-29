"""
Network collector for ports, services, interfaces, and connections
"""

import re
import socket
import subprocess
from typing import Dict, Any, List, Optional
from agent.collectors.base import BaseCollector
from agent.models.schema import Port, Service, Interface, Connections, ConnectionAttempts, NetworkPolicy

class NetworkCollector(BaseCollector):
    """Collects network-related information"""
    
    def __init__(self, timeout: int = 30):
        super().__init__(timeout)
        self.service_risks = {
            "ssh": "low",
            "http": "medium", 
            "https": "low",
            "telnet": "high",
            "ftp": "high",
            "smb": "high",
            "snmp": "medium",
            "rdp": "medium",
            "vnc": "high",
            "mysql": "medium",
            "postgresql": "medium",
            "redis": "medium",
            "mongodb": "medium",
            "elasticsearch": "medium"
        }
    
    def collect(self) -> Dict[str, Any]:
        """Collect all network information"""
        return {
            "open_ports": self._collect_open_ports(),
            "services": self._collect_services(),
            "interfaces": self._collect_interfaces(),
            "connections": self._collect_connections(),
            "policy": self._collect_network_policy()
        }
    
    def _collect_open_ports(self) -> List[Dict[str, Any]]:
        """Collect open ports using ss command"""
        ports = []
        
        try:
            # Get TCP and UDP listening ports
            result = self.run_command(["ss", "-tulpen"])
            
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                
                port_info = self._parse_ss_line(line)
                if port_info:
                    ports.append(port_info)
        
        except Exception as e:
            logger.error(f"Failed to collect open ports: {e}")
        
        return ports
    
    def _parse_ss_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse ss command output line"""
        # ss output format: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        parts = line.split()
        
        if len(parts) < 6:
            return None
        
        state = parts[0]
        local_addr = parts[3]
        
        # Parse address:port
        if ':' not in local_addr:
            return None
        
        addr, port = local_addr.rsplit(':', 1)
        
        # Determine protocol
        if line.startswith('tcp'):
            proto = "tcp"
        elif line.startswith('udp'):
            proto = "udp"
        else:
            return None
        
        # Extract process info if available
        process = "unknown"
        pid = 0
        
        if "users:" in line:
            # Parse process info: users:((\"process\",pid,fd))
            process_match = re.search(r'users:\(\(\\?"([^"]+)\\",(\d+),', line)
            if process_match:
                process = process_match.group(1)
                pid = self.parse_int(process_match.group(2))
        
        return {
            "proto": proto,
            "port": self.parse_int(port),
            "process": process,
            "pid": pid,
            "listen_addr": addr,
            "state": state.upper()
        }
    
    def _collect_services(self) -> List[Dict[str, Any]]:
        """Collect active services"""
        services = []
        
        # Common service ports
        service_ports = {
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            27017: "mongodb",
            9200: "elasticsearch"
        }
        
        # Get active ports
        open_ports = self._collect_open_ports()
        active_ports = {p["port"]: p for p in open_ports if p["state"] == "LISTEN"}
        
        for port, service_name in service_ports.items():
            if port in active_ports:
                port_info = active_ports[port]
                
                # Check if service is active via systemctl
                active = self._check_service_active(service_name)
                enabled = self._check_service_enabled(service_name)
                version = self._get_service_version(service_name)
                
                services.append({
                    "name": service_name,
                    "active": active,
                    "enabled": enabled,
                    "version": version,
                    "port": port,
                    "risk": self.service_risks.get(service_name, "medium")
                })
        
        return services
    
    def _check_service_active(self, service_name: str) -> bool:
        """Check if service is active"""
        try:
            result = self.run_command(["systemctl", "is-active", service_name], timeout=5)
            return result.stdout.strip() == "active"
        except:
            return False
    
    def _check_service_enabled(self, service_name: str) -> bool:
        """Check if service is enabled"""
        try:
            result = self.run_command(["systemctl", "is-enabled", service_name], timeout=5)
            return result.stdout.strip() == "enabled"
        except:
            return False
    
    def _get_service_version(self, service_name: str) -> Optional[str]:
        """Get service version if available"""
        version_commands = {
            "ssh": ["sshd", "-V"],
            "nginx": ["nginx", "-v"],
            "apache2": ["apache2", "-v"],
            "mysql": ["mysql", "--version"],
            "postgresql": ["psql", "--version"]
        }
        
        if service_name in version_commands:
            try:
                result = self.run_command(version_commands[service_name], timeout=5)
                return result.stdout.strip()
            except:
                pass
        
        return None
    
    def _collect_interfaces(self) -> List[Dict[str, Any]]:
        """Collect network interfaces"""
        interfaces = []
        
        try:
            # Get interface list
            result = self.run_command(["ip", "link", "show"])
            
            for line in result.stdout.split('\n'):
                if ':' in line and 'state' in line:
                    iface_info = self._parse_interface_line(line)
                    if iface_info:
                        # Get additional info
                        self._enrich_interface_info(iface_info)
                        interfaces.append(iface_info)
        
        except Exception as e:
            logger.error(f"Failed to collect interfaces: {e}")
        
        return interfaces
    
    def _parse_interface_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse interface line from ip link"""
        # Format: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        match = re.match(r'(\d+):\s+(\w+):\s+.*state\s+(\w+)', line)
        
        if not match:
            return None
        
        iface_num, name, state = match.groups()
        
        # Determine interface type
        iface_type = "ethernet"
        if name.startswith("wlan") or name.startswith("wifi"):
            iface_type = "wifi"
        elif name.startswith("docker") or name.startswith("veth"):
            iface_type = "virtual"
        
        # Normalize state to valid values
        normalized_state = "up" if state.lower() == "up" else "down"
        
        return {
            "name": name,
            "type": iface_type,
            "state": normalized_state,
            "ipv4": None,
            "ipv6": None,
            "mac": "",
            "default_route": False,
            "speed_mbps": 0,
            "ssid": None,
            "signal_dbm": 0,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_delta": 0,
            "tx_delta": 0
        }
    
    def _enrich_interface_info(self, iface: Dict[str, Any]):
        """Enrich interface with additional information"""
        name = iface["name"]
        
        # Get IP addresses
        try:
            result = self.run_command(["ip", "addr", "show", name])
            self._parse_interface_addresses(result.stdout, iface)
        except:
            pass
        
        # Get MAC address
        try:
            result = self.run_command(["ip", "link", "show", name])
            mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', result.stdout)
            if mac_match:
                iface["mac"] = mac_match.group(1)
        except:
            pass
        
        # Get statistics
        try:
            stats = self.get_file_content(f"/sys/class/net/{name}/statistics/rx_bytes")
            if stats:
                iface["rx_bytes"] = self.parse_int(stats)
            
            stats = self.get_file_content(f"/sys/class/net/{name}/statistics/tx_bytes")
            if stats:
                iface["tx_bytes"] = self.parse_int(stats)
        except:
            pass
        
        # Check if default route
        try:
            result = self.run_command(["ip", "route", "show", "default"])
            iface["default_route"] = name in result.stdout
        except:
            pass
        
        # Get speed (if ethernet)
        if iface["type"] == "ethernet":
            try:
                result = self.run_command(["ethtool", name], timeout=5)
                speed_match = re.search(r'Speed:\s+(\d+)Mb/s', result.stdout)
                if speed_match:
                    iface["speed_mbps"] = self.parse_int(speed_match.group(1))
            except:
                pass
        
        # Get WiFi info (if applicable)
        if iface["type"] == "wifi":
            try:
                result = self.run_command(["iw", name, "link"], timeout=5)
                ssid_match = re.search(r'SSID:\s+(.+)', result.stdout)
                if ssid_match:
                    iface["ssid"] = ssid_match.group(1).strip()
                
                signal_match = re.search(r'signal:\s+(-\d+)\s+dBm', result.stdout)
                if signal_match:
                    iface["signal_dbm"] = self.parse_int(signal_match.group(1))
            except:
                pass
    
    def _parse_interface_addresses(self, output: str, iface: Dict[str, Any]):
        """Parse IP addresses from ip addr output"""
        # Look for inet and inet6 lines
        inet_match = re.search(r'inet\s+([0-9.]+)', output)
        if inet_match:
            iface["ipv4"] = inet_match.group(1)
        
        inet6_match = re.search(r'inet6\s+([0-9a-f:]+)', output)
        if inet6_match:
            iface["ipv6"] = inet6_match.group(1)
    
    def _collect_connections(self) -> Dict[str, Any]:
        """Collect connection statistics"""
        connections = {
            "by_state": {"ESTABLISHED": 0, "TIME_WAIT": 0, "LISTEN": 0, "OTHER": 0},
            "attempts": {"icmp": 0, "ssh": {"success": 0, "fail": 0}, "telnet": {"success": 0, "fail": 0}}
        }
        
        try:
            # Get connection summary
            result = self.run_command(["ss", "-s"])
            
            for line in result.stdout.split('\n'):
                if 'ESTAB' in line:
                    est_match = re.search(r'(\d+)\s+ESTAB', line)
                    if est_match:
                        connections["by_state"]["ESTABLISHED"] = self.parse_int(est_match.group(1))
                
                elif 'TIME-WAIT' in line:
                    tw_match = re.search(r'(\d+)\s+TIME-WAIT', line)
                    if tw_match:
                        connections["by_state"]["TIME_WAIT"] = self.parse_int(tw_match.group(1))
                
                elif 'LISTEN' in line:
                    listen_match = re.search(r'(\d+)\s+LISTEN', line)
                    if listen_match:
                        connections["by_state"]["LISTEN"] = self.parse_int(listen_match.group(1))
        
        except Exception as e:
            logger.error(f"Failed to collect connections: {e}")
        
        return connections
    
    def _collect_network_policy(self) -> Dict[str, bool]:
        """Collect network policy information"""
        policy = {
            "wifi_enabled": False,
            "should_disable_wifi": False
        }
        
        try:
            # Check if WiFi is enabled
            result = self.run_command(["nmcli", "radio", "wifi"], timeout=5)
            policy["wifi_enabled"] = "enabled" in result.stdout.lower()
            
            # Check if we have ethernet connection
            result = self.run_command(["ip", "link", "show"])
            has_ethernet = any("eth" in line and "state UP" in line for line in result.stdout.split('\n'))
            
            # Should disable WiFi if ethernet is available
            policy["should_disable_wifi"] = has_ethernet and policy["wifi_enabled"]
        
        except Exception as e:
            logger.error(f"Failed to collect network policy: {e}")
        
        return policy
