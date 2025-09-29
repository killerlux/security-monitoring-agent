"""
USB device collector
"""

import re
import subprocess
from typing import Dict, Any, List
from datetime import datetime
from agent.collectors.base import BaseCollector

class USBCollector(BaseCollector):
    """Collects USB device information"""
    
    def collect(self) -> Dict[str, Any]:
        """Collect USB device information"""
        return {
            "recent_events": self._collect_recent_usb_events()
        }
    
    def _collect_recent_usb_events(self) -> List[Dict[str, Any]]:
        """Collect recent USB events from system logs"""
        events = []
        
        try:
            # Get USB devices using lsusb
            result = self.run_command(["lsusb"], timeout=10)
            current_devices = self._parse_lsusb_output(result.stdout)
            
            # For now, we'll simulate recent events
            # In a real implementation, you'd compare with previous state
            # and parse system logs for add/remove events
            
            # Check journalctl for USB events (if available)
            try:
                journal_result = self.run_command([
                    "journalctl", "-u", "systemd-udevd", "--since", "-24h", "--no-pager"
                ], timeout=15)
                
                usb_events = self._parse_usb_journal(journal_result.stdout)
                events.extend(usb_events)
            
            except Exception as e:
                logger.debug(f"Could not parse USB journal events: {e}")
        
        except Exception as e:
            logger.error(f"Failed to collect USB events: {e}")
        
        return events
    
    def _parse_lsusb_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse lsusb command output"""
        devices = []
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            # lsusb format: Bus 001 Device 002: ID 1234:5678 Device Name
            match = re.match(
                r'Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)',
                line
            )
            
            if match:
                bus, device, vendor_id, product_id, name = match.groups()
                
                devices.append({
                    "bus": bus,
                    "device": device,
                    "vendor_id": vendor_id,
                    "product_id": product_id,
                    "name": name.strip()
                })
        
        return devices
    
    def _parse_usb_journal(self, output: str) -> List[Dict[str, Any]]:
        """Parse USB events from journalctl"""
        events = []
        
        lines = output.split('\n')
        for line in lines:
            if not line.strip():
                continue
            
            # Look for USB add/remove events
            if "add" in line.lower() and "usb" in line.lower():
                event = self._parse_usb_event_line(line, "add")
                if event:
                    events.append(event)
            
            elif "remove" in line.lower() and "usb" in line.lower():
                event = self._parse_usb_event_line(line, "remove")
                if event:
                    events.append(event)
        
        return events
    
    def _parse_usb_event_line(self, line: str, action: str) -> Dict[str, Any]:
        """Parse individual USB event line"""
        # Extract timestamp from journal line
        timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        timestamp = datetime.now().isoformat()
        
        if timestamp_match:
            timestamp = timestamp_match.group(1)
        
        # Try to extract device information
        device_match = re.search(r'usb\s+(\d+-\d+):\s+([^:]+)', line, re.IGNORECASE)
        
        device = "unknown"
        vendor_id = "0000"
        product_id = "0000"
        device_class = "unknown"
        
        if device_match:
            device = device_match.group(1)
        
        return {
            "action": action,
            "time": timestamp,
            "device": device,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "class_name": device_class
        }
    
    def get_current_usb_devices(self) -> List[Dict[str, Any]]:
        """Get current USB devices (for comparison)"""
        try:
            result = self.run_command(["lsusb"], timeout=10)
            return self._parse_lsusb_output(result.stdout)
        except Exception as e:
            logger.error(f"Failed to get current USB devices: {e}")
            return []
    
    def monitor_usb_changes(self, previous_devices: List[Dict[str, Any]], 
                           current_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compare previous and current USB devices to detect changes"""
        events = []
        
        # Create sets for comparison
        prev_set = {(d["vendor_id"], d["product_id"]) for d in previous_devices}
        curr_set = {(d["vendor_id"], d["product_id"]) for d in current_devices}
        
        # Find added devices
        added = curr_set - prev_set
        for vendor_id, product_id in added:
            device = next((d for d in current_devices 
                          if d["vendor_id"] == vendor_id and d["product_id"] == product_id), None)
            if device:
                events.append({
                    "action": "add",
                    "time": datetime.now().isoformat(),
                    "device": device["name"],
                    "vendor_id": vendor_id,
                    "product_id": product_id,
                    "class_name": self._get_device_class(vendor_id, product_id)
                })
        
        # Find removed devices
        removed = prev_set - curr_set
        for vendor_id, product_id in removed:
            device = next((d for d in previous_devices 
                          if d["vendor_id"] == vendor_id and d["product_id"] == product_id), None)
            if device:
                events.append({
                    "action": "remove",
                    "time": datetime.now().isoformat(),
                    "device": device["name"],
                    "vendor_id": vendor_id,
                    "product_id": product_id,
                    "class_name": self._get_device_class(vendor_id, product_id)
                })
        
        return events
    
    def _get_device_class(self, vendor_id: str, product_id: str) -> str:
        """Determine device class based on vendor/product ID"""
        # Common device classes (simplified)
        device_classes = {
            ("1d6b", "0001"): "hub",  # Linux Foundation root hub
            ("1d6b", "0002"): "hub",  # Linux Foundation root hub
            ("046d", "c52b"): "keyboard",  # Logitech keyboard
            ("046d", "c534"): "mouse",     # Logitech mouse
            ("045e", "0040"): "keyboard",  # Microsoft keyboard
            ("045e", "0047"): "mouse",     # Microsoft mouse
        }
        
        return device_classes.get((vendor_id.lower(), product_id.lower()), "unknown")
