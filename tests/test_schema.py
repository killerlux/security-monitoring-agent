"""
Tests for JSON Schema and Pydantic models
"""

import json
import pytest
from datetime import datetime
from agent.models.schema import (
    MonitoringOutput, Network, System, USB, AppSec, Diff,
    Port, Service, Interface, CPU, Memory, Disk, Process
)

class TestSchema:
    """Test JSON Schema validation and Pydantic models"""
    
    def test_port_model(self):
        """Test Port model validation"""
        port = Port(
            proto="tcp",
            port=22,
            process="sshd",
            pid=1234,
            listen_addr="0.0.0.0",
            state="LISTEN"
        )
        
        assert port.proto == "tcp"
        assert port.port == 22
        assert port.process == "sshd"
        assert port.pid == 1234
        assert port.listen_addr == "0.0.0.0"
        assert port.state == "LISTEN"
    
    def test_port_invalid_protocol(self):
        """Test Port model with invalid protocol"""
        with pytest.raises(ValueError):
            Port(
                proto="invalid",
                port=22,
                process="sshd",
                pid=1234,
                listen_addr="0.0.0.0",
                state="LISTEN"
            )
    
    def test_port_invalid_port_range(self):
        """Test Port model with invalid port range"""
        with pytest.raises(ValueError):
            Port(
                proto="tcp",
                port=70000,  # Invalid port number
                process="sshd",
                pid=1234,
                listen_addr="0.0.0.0",
                state="LISTEN"
            )
    
    def test_service_model(self):
        """Test Service model validation"""
        service = Service(
            name="ssh",
            active=True,
            enabled=True,
            version="OpenSSH_8.2p1",
            port=22,
            risk="low"
        )
        
        assert service.name == "ssh"
        assert service.active is True
        assert service.enabled is True
        assert service.version == "OpenSSH_8.2p1"
        assert service.port == 22
        assert service.risk == "low"
    
    def test_interface_model(self):
        """Test Interface model validation"""
        interface = Interface(
            name="eth0",
            type="ethernet",
            state="up",
            ipv4="192.168.1.100",
            ipv6="::1",
            mac="aa:bb:cc:dd:ee:ff",
            default_route=True,
            speed_mbps=1000,
            ssid=None,
            signal_dbm=0,
            rx_bytes=1024000,
            tx_bytes=512000,
            rx_delta=1024,
            tx_delta=512
        )
        
        assert interface.name == "eth0"
        assert interface.type == "ethernet"
        assert interface.state == "up"
        assert interface.ipv4 == "192.168.1.100"
        assert interface.ipv6 == "::1"
        assert interface.mac == "aa:bb:cc:dd:ee:ff"
        assert interface.default_route is True
        assert interface.speed_mbps == 1000
        assert interface.ssid is None
        assert interface.signal_dbm == 0
        assert interface.rx_bytes == 1024000
        assert interface.tx_bytes == 512000
        assert interface.rx_delta == 1024
        assert interface.tx_delta == 512
    
    def test_cpu_model(self):
        """Test CPU model validation"""
        cpu = CPU(
            load1=0.5,
            load5=0.8,
            load15=1.2,
            user_pct=25.0,
            system_pct=10.0,
            iowait_pct=5.0
        )
        
        assert cpu.load1 == 0.5
        assert cpu.load5 == 0.8
        assert cpu.load15 == 1.2
        assert cpu.user_pct == 25.0
        assert cpu.system_pct == 10.0
        assert cpu.iowait_pct == 5.0
    
    def test_memory_model(self):
        """Test Memory model validation"""
        memory = Memory(
            total_mb=8192,
            used_mb=4096,
            free_mb=4096,
            cached_mb=1024
        )
        
        assert memory.total_mb == 8192
        assert memory.used_mb == 4096
        assert memory.free_mb == 4096
        assert memory.cached_mb == 1024
    
    def test_monitoring_output_model(self):
        """Test complete MonitoringOutput model"""
        # Create minimal valid data
        from agent.models.schema import create_example_output
        
        output = create_example_output()
        
        # Validate the model
        assert isinstance(output, MonitoringOutput)
        assert output.host is not None
        assert output.run_id is not None
        assert isinstance(output.timestamp, datetime)
        assert len(output.network.open_ports) > 0
        assert len(output.network.services) > 0
        assert len(output.network.interfaces) > 0
        assert output.system.cpu.load1 >= 0
        assert output.system.memory.total_mb > 0
        assert isinstance(output.diff.alerts, list)
    
    def test_json_serialization(self):
        """Test JSON serialization/deserialization"""
        from agent.models.schema import create_example_output
        
        output = create_example_output()
        
        # Convert to dict
        data = output.dict()
        
        # Convert to JSON
        json_str = json.dumps(data, default=str)
        
        # Parse back
        parsed_data = json.loads(json_str)
        
        # Validate structure
        assert "timestamp" in parsed_data
        assert "host" in parsed_data
        assert "run_id" in parsed_data
        assert "network" in parsed_data
        assert "system" in parsed_data
        assert "usb" in parsed_data
        assert "appsec" in parsed_data
        assert "diff" in parsed_data
    
    def test_schema_validation(self):
        """Test JSON Schema validation"""
        from agent.models.schema import MONITORING_SCHEMA, create_example_output
        import jsonschema
        
        # Create example data
        output = create_example_output()
        data = output.dict()
        
        # Validate against schema
        jsonschema.validate(data, MONITORING_SCHEMA)
        
        # This should not raise an exception
        assert True
    
    def test_required_fields(self):
        """Test that required fields are enforced"""
        with pytest.raises(ValueError):
            # Missing required fields
            MonitoringOutput(
                timestamp=datetime.now(),
                # Missing host, run_id, etc.
            )
    
    def test_run_id_generation(self):
        """Test automatic run_id generation"""
        output = MonitoringOutput(
            timestamp=datetime.now(),
            host="test.local",
            # run_id not provided - should be auto-generated
            network=Network(
                open_ports=[],
                services=[],
                interfaces=[],
                connections={"by_state": {}, "attempts": {}},
                policy={"wifi_enabled": False, "should_disable_wifi": False}
            ),
            system=System(
                cpu=CPU(load1=0, load5=0, load15=0, user_pct=0, system_pct=0, iowait_pct=0),
                memory=Memory(total_mb=0, used_mb=0, free_mb=0, cached_mb=0),
                disk=[],
                top_processes={"by_cpu": [], "by_mem": []}
            ),
            usb=USB(recent_events=[]),
            appsec=AppSec(
                http_checks=[],
                sbom={"format": "CycloneDX", "components": []},
                dast={"tool": "zap", "issues": []},
                policies=[]
            ),
            diff=Diff(
                new_open_ports=[],
                closed_ports=[],
                service_state_changes=[],
                alerts=[]
            )
        )
        
        # run_id should be auto-generated
        assert output.run_id is not None
        assert len(output.run_id) > 0
