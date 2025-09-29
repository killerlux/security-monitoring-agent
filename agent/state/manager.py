"""
State Manager for Security Monitoring Agent
Handles caching and delta calculations
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
import hashlib

class StateManager:
    """Manages persistent state and calculates deltas between runs"""
    
    def __init__(self, state_dir: str = "/var/lib/security-monitor"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self.last_run_file = self.state_dir / "last-run.json"
        
        # Initialize state
        self._load_state()
    
    def _load_state(self):
        """Load previous state from disk"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    self.state = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.state = self._get_empty_state()
        else:
            self.state = self._get_empty_state()
    
    def _get_empty_state(self) -> Dict[str, Any]:
        """Return empty state structure"""
        return {
            "last_update": None,
            "network": {
                "open_ports": [],
                "interfaces": {},
                "connection_attempts": {}
            },
            "system": {
                "top_processes": []
            },
            "usb": {
                "events": []
            },
            "alerts": {},
            "baseline": {
                "open_ports": [],
                "services": [],
                "interfaces": []
            }
        }
    
    def save_state(self, new_data: Dict[str, Any]):
        """Save current state to disk"""
        self.state["last_update"] = datetime.now().isoformat()
        
        # Update network state
        if "network" in new_data:
            self.state["network"]["open_ports"] = new_data["network"].get("open_ports", [])
            
            # Store interface deltas
            for iface in new_data["network"].get("interfaces", []):
                iface_name = iface["name"]
                if iface_name in self.state["network"]["interfaces"]:
                    old_iface = self.state["network"]["interfaces"][iface_name]
                    iface["rx_delta"] = iface["rx_bytes"] - old_iface.get("rx_bytes", 0)
                    iface["tx_delta"] = iface["tx_bytes"] - old_iface.get("tx_bytes", 0)
                else:
                    iface["rx_delta"] = 0
                    iface["tx_delta"] = 0
                
                self.state["network"]["interfaces"][iface_name] = iface
        
        # Update baseline after first run
        if self.state["last_update"] is None:
            self.state["baseline"]["open_ports"] = self.state["network"]["open_ports"].copy()
        
        # Save to disk
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
        
        # Save last run data
        with open(self.last_run_file, 'w') as f:
            json.dump(new_data, f, indent=2, default=str)
    
    def get_port_deltas(self, current_ports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Calculate port changes from baseline"""
        baseline_ports = self.state["baseline"]["open_ports"]
        
        # Create sets for comparison
        baseline_set = {(p["proto"], p["port"]) for p in baseline_ports}
        current_set = {(p["proto"], p["port"]) for p in current_ports}
        
        new_ports = current_set - baseline_set
        closed_ports = baseline_set - current_set
        
        return {
            "new_open_ports": [{"proto": p[0], "port": p[1]} for p in new_ports],
            "closed_ports": [{"proto": p[0], "port": p[1]} for p in closed_ports]
        }
    
    def get_service_changes(self, current_services: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Detect service state changes"""
        changes = []
        
        # This would require storing previous service states
        # For now, return empty list
        return changes
    
    def get_interface_deltas(self, current_interfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get interface deltas with calculated RX/TX differences"""
        result = []
        
        for iface in current_interfaces:
            iface_name = iface["name"]
            
            if iface_name in self.state["network"]["interfaces"]:
                old_iface = self.state["network"]["interfaces"][iface_name]
                iface["rx_delta"] = iface["rx_bytes"] - old_iface.get("rx_bytes", 0)
                iface["tx_delta"] = iface["tx_bytes"] - old_iface.get("tx_bytes", 0)
            else:
                iface["rx_delta"] = 0
                iface["tx_delta"] = 0
            
            result.append(iface)
        
        return result
    
    def get_connection_attempt_deltas(self, current_attempts: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate connection attempt deltas"""
        # This would track SSH/Telnet/ICMP attempts over time
        # For now, return current attempts
        return current_attempts
    
    def add_usb_event(self, event: Dict[str, Any]):
        """Add USB event to state"""
        event["time"] = datetime.now().isoformat()
        self.state["usb"]["events"].append(event)
        
        # Keep only last 100 events
        if len(self.state["usb"]["events"]) > 100:
            self.state["usb"]["events"] = self.state["usb"]["events"][-100:]
    
    def get_recent_usb_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent USB events within specified hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_events = []
        
        for event in self.state["usb"]["events"]:
            event_time = datetime.fromisoformat(event["time"])
            if event_time > cutoff:
                recent_events.append(event)
        
        return recent_events
    
    def should_alert(self, alert_key: str, severity: str, ttl_hours: int = 1) -> bool:
        """Check if alert should be generated (deduplication)"""
        now = datetime.now()
        
        if alert_key not in self.state["alerts"]:
            self.state["alerts"][alert_key] = {
                "last_alert": now.isoformat(),
                "severity": severity,
                "count": 1
            }
            return True
        
        last_alert_time = datetime.fromisoformat(self.state["alerts"][alert_key]["last_alert"])
        time_diff = now - last_alert_time
        
        # Allow alert if TTL has passed
        if time_diff > timedelta(hours=ttl_hours):
            self.state["alerts"][alert_key]["last_alert"] = now.isoformat()
            self.state["alerts"][alert_key]["count"] += 1
            return True
        
        return False
    
    def get_alert_hash(self, message: str, evidence: Dict[str, Any]) -> str:
        """Generate hash for alert deduplication"""
        content = f"{message}:{json.dumps(evidence, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old state data"""
        cutoff = datetime.now() - timedelta(days=days)
        
        # Clean old USB events
        self.state["usb"]["events"] = [
            event for event in self.state["usb"]["events"]
            if datetime.fromisoformat(event["time"]) > cutoff
        ]
        
        # Clean old alerts
        alert_keys_to_remove = []
        for key, alert_data in self.state["alerts"].items():
            last_alert = datetime.fromisoformat(alert_data["last_alert"])
            if last_alert < cutoff:
                alert_keys_to_remove.append(key)
        
        for key in alert_keys_to_remove:
            del self.state["alerts"][key]
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get summary of current state"""
        return {
            "last_update": self.state.get("last_update"),
            "total_alerts": len(self.state.get("alerts", {})),
            "usb_events_count": len(self.state.get("usb", {}).get("events", [])),
            "baseline_ports_count": len(self.state.get("baseline", {}).get("open_ports", [])),
            "state_file_size": self.state_file.stat().st_size if self.state_file.exists() else 0
        }
