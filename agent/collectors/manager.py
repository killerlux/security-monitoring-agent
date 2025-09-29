"""
Collector Manager - orchestrates all data collection
"""

import logging
import socket
from datetime import datetime
from typing import Dict, Any, List

from agent.collectors.network import NetworkCollector
from agent.collectors.system import SystemCollector
from agent.collectors.usb import USBCollector
from agent.appsec.collector import AppSecCollector
from agent.models.schema import MonitoringOutput, Network, System, USB, AppSec, Diff, Alert
from agent.state.manager import StateManager

logger = logging.getLogger(__name__)

class CollectorManager:
    """Manages all data collectors and orchestrates monitoring runs"""
    
    def __init__(self, config_path: str, state_manager: StateManager):
        self.config_path = config_path
        self.state_manager = state_manager
        
        # Initialize collectors
        self.network_collector = NetworkCollector()
        self.system_collector = SystemCollector()
        self.usb_collector = USBCollector()
        self.appsec_collector = AppSecCollector()
        
        # Load configuration
        self.config = self._load_config()
        
        # Alert thresholds
        self.thresholds = {
            "cpu_load1": 2.0,
            "memory_pct": 90.0,
            "disk_pct": 85.0,
            "iowait_pct": 20.0,
            "ssh_fail_threshold": 5,
            "icmp_threshold": 100
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            import yaml
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load config from {self.config_path}: {e}")
            return {}
    
    def collect_all(self) -> MonitoringOutput:
        """Collect all monitoring data and return structured output"""
        logger.info("Starting comprehensive monitoring collection")
        
        # Collect raw data
        network_data = self.network_collector.collect()
        system_data = self.system_collector.collect()
        usb_data = self.usb_collector.collect()
        appsec_data = self.appsec_collector.collect()
        
        # Calculate deltas and generate alerts
        diff_data = self._calculate_diffs(network_data, system_data)
        
        # Create structured output
        monitoring_output = MonitoringOutput(
            timestamp=datetime.now(),
            host=socket.gethostname(),
            run_id=str(datetime.now().timestamp()),
            network=Network(**network_data),
            system=System(**system_data),
            usb=USB(**usb_data),
            appsec=AppSec(**appsec_data),
            diff=Diff(**diff_data)
        )
        
        # Save state for next run
        self.state_manager.save_state(monitoring_output.model_dump())
        
        logger.info("Monitoring collection completed successfully")
        return monitoring_output
    
    def _calculate_diffs(self, network_data: Dict[str, Any], 
                        system_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate differences from baseline and generate alerts"""
        diff_data = {
            "new_open_ports": [],
            "closed_ports": [],
            "service_state_changes": [],
            "alerts": []
        }
        
        # Calculate port deltas
        port_deltas = self.state_manager.get_port_deltas(network_data["open_ports"])
        diff_data["new_open_ports"] = port_deltas["new_open_ports"]
        diff_data["closed_ports"] = port_deltas["closed_ports"]
        
        # Generate alerts for new ports
        for port in diff_data["new_open_ports"]:
            alert = self._create_port_alert(port)
            if alert:
                diff_data["alerts"].append(alert)
        
        # Generate system alerts
        system_alerts = self._generate_system_alerts(system_data)
        diff_data["alerts"].extend(system_alerts)
        
        # Generate network policy alerts
        policy_alerts = self._generate_policy_alerts(network_data)
        diff_data["alerts"].extend(policy_alerts)
        
        # Generate service alerts
        service_alerts = self._generate_service_alerts(network_data["services"])
        diff_data["alerts"].extend(service_alerts)
        
        return diff_data
    
    def _create_port_alert(self, port: Dict[str, Any]) -> Alert:
        """Create alert for new open port"""
        port_num = port["port"]
        proto = port["proto"]
        
        # Check if this is a high-risk port
        high_risk_ports = [23, 21, 135, 139, 445, 1433, 3389]
        
        if port_num in high_risk_ports:
            return Alert(
                severity="high",
                code="NEW_HIGH_RISK_PORT",
                message=f"New high-risk port opened: {proto}/{port_num}",
                evidence={"port": port_num, "proto": proto}
            )
        else:
            return Alert(
                severity="warn",
                code="NEW_OPEN_PORT",
                message=f"New port opened: {proto}/{port_num}",
                evidence={"port": port_num, "proto": proto}
            )
    
    def _generate_system_alerts(self, system_data: Dict[str, Any]) -> List[Alert]:
        """Generate system resource alerts"""
        alerts = []
        
        # CPU load alerts
        cpu_info = system_data["cpu"]
        if cpu_info["load1"] > self.thresholds["cpu_load1"]:
            alert_key = f"cpu_load_{cpu_info['load1']}"
            if self.state_manager.should_alert(alert_key, "warn"):
                alerts.append(Alert(
                    severity="warn",
                    code="HIGH_CPU_LOAD",
                    message=f"High CPU load: {cpu_info['load1']:.2f}",
                    evidence={"load1": cpu_info["load1"], "threshold": self.thresholds["cpu_load1"]}
                ))
        
        # Memory alerts
        memory_info = system_data["memory"]
        memory_pct = (memory_info["used_mb"] / memory_info["total_mb"]) * 100
        if memory_pct > self.thresholds["memory_pct"]:
            alert_key = f"memory_pct_{memory_pct:.1f}"
            if self.state_manager.should_alert(alert_key, "warn"):
                alerts.append(Alert(
                    severity="warn",
                    code="HIGH_MEMORY_USAGE",
                    message=f"High memory usage: {memory_pct:.1f}%",
                    evidence={"used_pct": memory_pct, "threshold": self.thresholds["memory_pct"]}
                ))
        
        # Disk alerts
        for disk in system_data["disk"]:
            if disk["used_pct"] > self.thresholds["disk_pct"]:
                alert_key = f"disk_pct_{disk['mount']}_{disk['used_pct']:.1f}"
                if self.state_manager.should_alert(alert_key, "warn"):
                    alerts.append(Alert(
                        severity="warn",
                        code="HIGH_DISK_USAGE",
                        message=f"High disk usage on {disk['mount']}: {disk['used_pct']:.1f}%",
                        evidence={"mount": disk["mount"], "used_pct": disk["used_pct"], 
                                "threshold": self.thresholds["disk_pct"]}
                    ))
        
        # I/O wait alerts
        if cpu_info["iowait_pct"] > self.thresholds["iowait_pct"]:
            alert_key = f"iowait_{cpu_info['iowait_pct']:.1f}"
            if self.state_manager.should_alert(alert_key, "warn"):
                alerts.append(Alert(
                    severity="warn",
                    code="HIGH_IO_WAIT",
                    message=f"High I/O wait: {cpu_info['iowait_pct']:.1f}%",
                    evidence={"iowait_pct": cpu_info["iowait_pct"], 
                            "threshold": self.thresholds["iowait_pct"]}
                ))
        
        return alerts
    
    def _generate_policy_alerts(self, network_data: Dict[str, Any]) -> List[Alert]:
        """Generate network policy alerts"""
        alerts = []
        
        policy = network_data["policy"]
        
        # WiFi policy alert
        if policy["should_disable_wifi"]:
            alert_key = "wifi_policy_violation"
            if self.state_manager.should_alert(alert_key, "warn"):
                alerts.append(Alert(
                    severity="warn",
                    code="POLICY_WIFI_ENABLED",
                    message="Wi-Fi actif alors que la politique exige Ethernet",
                    evidence={"wifi_enabled": policy["wifi_enabled"]}
                ))
        
        return alerts
    
    def _generate_service_alerts(self, services: List[Dict[str, Any]]) -> List[Alert]:
        """Generate service-specific alerts"""
        alerts = []
        
        for service in services:
            service_name = service["name"]
            is_active = service["active"]
            risk_level = service["risk"]
            
            # High-risk services should not be active
            if risk_level == "high" and is_active:
                alert_key = f"high_risk_service_{service_name}"
                if self.state_manager.should_alert(alert_key, "high"):
                    alerts.append(Alert(
                        severity="high",
                        code="HIGH_RISK_SERVICE_ACTIVE",
                        message=f"Service à haut risque actif: {service_name}",
                        evidence={"service": service_name, "port": service["port"]}
                    ))
        
        return alerts
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of monitoring status"""
        return {
            "collectors": {
                "network": "NetworkCollector",
                "system": "SystemCollector", 
                "usb": "USBCollector",
                "appsec": "AppSecCollector"
            },
            "thresholds": self.thresholds,
            "state_summary": self.state_manager.get_state_summary()
        }
