"""
Tests for data collectors
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from agent.collectors.network import NetworkCollector
from agent.collectors.system import SystemCollector
from agent.collectors.usb import USBCollector
from agent.collectors.base import BaseCollector

class TestBaseCollector:
    """Test base collector functionality"""
    
    def test_init(self):
        """Test collector initialization"""
        collector = BaseCollector(timeout=60)
        assert collector.timeout == 60
    
    def test_parse_int(self):
        """Test integer parsing"""
        collector = BaseCollector()
        
        assert collector.parse_int("123") == 123
        assert collector.parse_int("0") == 0
        assert collector.parse_int("invalid", default=42) == 42
        assert collector.parse_int(None, default=10) == 10
    
    def test_parse_float(self):
        """Test float parsing"""
        collector = BaseCollector()
        
        assert collector.parse_float("123.45") == 123.45
        assert collector.parse_float("0.0") == 0.0
        assert collector.parse_float("invalid", default=42.0) == 42.0
        assert collector.parse_float(None, default=10.0) == 10.0

class TestNetworkCollector:
    """Test network collector"""
    
    def test_init(self):
        """Test network collector initialization"""
        collector = NetworkCollector()
        assert collector.timeout == 30
        assert "ssh" in collector.service_risks
        assert collector.service_risks["ssh"] == "low"
        assert collector.service_risks["telnet"] == "high"
    
    @patch('agent.collectors.network.subprocess.run')
    def test_collect_open_ports(self, mock_run):
        """Test open ports collection"""
        # Mock ss command output
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
State    Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN   0      128    0.0.0.0:22        0.0.0.0:*       users:(("sshd",pid=1234,fd=3))
LISTEN   0      128    127.0.0.1:80      0.0.0.0:*       users:(("nginx",pid=5678,fd=4))
"""
        mock_run.return_value = mock_result
        
        collector = NetworkCollector()
        ports = collector._collect_open_ports()
        
        assert len(ports) == 2
        assert ports[0]["proto"] == "tcp"
        assert ports[0]["port"] == 22
        assert ports[0]["process"] == "sshd"
        assert ports[0]["pid"] == 1234
        assert ports[0]["listen_addr"] == "0.0.0.0"
        assert ports[0]["state"] == "LISTEN"
        
        assert ports[1]["port"] == 80
        assert ports[1]["process"] == "nginx"
    
    def test_parse_ss_line(self):
        """Test ss line parsing"""
        collector = NetworkCollector()
        
        # Valid TCP line
        line = "LISTEN   0      128    0.0.0.0:22        0.0.0.0:*       users:((\"sshd\",pid=1234,fd=3))"
        result = collector._parse_ss_line(line)
        
        assert result is not None
        assert result["proto"] == "tcp"
        assert result["port"] == 22
        assert result["process"] == "sshd"
        assert result["pid"] == 1234
        assert result["listen_addr"] == "0.0.0.0"
        assert result["state"] == "LISTEN"
        
        # Invalid line
        invalid_line = "INVALID LINE"
        result = collector._parse_ss_line(invalid_line)
        assert result is None
    
    @patch('agent.collectors.network.subprocess.run')
    def test_check_service_active(self, mock_run):
        """Test service active check"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "active\n"
        mock_run.return_value = mock_result
        
        collector = NetworkCollector()
        is_active = collector._check_service_active("ssh")
        
        assert is_active is True
        mock_run.assert_called_with(["systemctl", "is-active", "ssh"], timeout=5)
    
    @patch('agent.collectors.network.subprocess.run')
    def test_check_service_enabled(self, mock_run):
        """Test service enabled check"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "enabled\n"
        mock_run.return_value = mock_result
        
        collector = NetworkCollector()
        is_enabled = collector._check_service_enabled("ssh")
        
        assert is_enabled is True
        mock_run.assert_called_with(["systemctl", "is-enabled", "ssh"], timeout=5)

class TestSystemCollector:
    """Test system collector"""
    
    def test_init(self):
        """Test system collector initialization"""
        collector = SystemCollector()
        assert collector.timeout == 30
    
    @patch('agent.collectors.system.SystemCollector.get_file_content')
    def test_collect_cpu_info(self, mock_get_content):
        """Test CPU info collection"""
        # Mock /proc/loadavg
        mock_get_content.side_effect = [
            "0.50 0.80 1.20 2/123 4567",  # loadavg
            """cpu  123456 7890 12345 234567 5678 0 1234 0 0 0
cpu0 12345 789 1234 23456 567 0 123 0 0 0
"""  # /proc/stat
        ]
        
        collector = SystemCollector()
        cpu_info = collector._collect_cpu_info()
        
        assert cpu_info["load1"] == 0.50
        assert cpu_info["load5"] == 0.80
        assert cpu_info["load15"] == 1.20
        assert cpu_info["user_pct"] > 0
        assert cpu_info["system_pct"] > 0
        assert cpu_info["iowait_pct"] > 0
    
    @patch('agent.collectors.system.subprocess.run')
    def test_collect_memory_info(self, mock_run):
        """Test memory info collection"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
              total        used        free      shared  buff/cache   available
Mem:           8192        4096        2048         512        2048        3584
Swap:          2048           0        2048
"""
        mock_run.return_value = mock_result
        
        collector = SystemCollector()
        memory_info = collector._collect_memory_info()
        
        assert memory_info["total_mb"] == 8192
        assert memory_info["used_mb"] == 4096
        assert memory_info["free_mb"] == 2048
        assert memory_info["cached_mb"] == 2048
    
    @patch('agent.collectors.system.subprocess.run')
    def test_collect_disk_info(self, mock_run):
        """Test disk info collection"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
Filesystem      Type      Size  Used Avail Use% Mounted on
/dev/sda1       ext4      100G   45G   50G  48% /
tmpfs           tmpfs     2.0G     0  2.0G   0% /tmp
"""
        mock_run.return_value = mock_result
        
        collector = SystemCollector()
        disks = collector._collect_disk_info()
        
        assert len(disks) == 1  # Only / should be included
        assert disks[0]["mount"] == "/"
        assert disks[0]["fs"] == "ext4"
        assert disks[0]["size_gb"] == 100.0
        assert disks[0]["used_gb"] == 45.0
        assert disks[0]["used_pct"] == 48.0
    
    @patch('agent.collectors.system.subprocess.run')
    def test_collect_top_processes(self, mock_run):
        """Test top processes collection"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1234  5.0  2.0  12345  6789 ?        Ss   10:00   0:01 sshd
www-data  5678  1.0  8.0  23456  8901 ?        S    10:01   0:00 nginx
"""
        mock_run.return_value = mock_result
        
        collector = SystemCollector()
        top_processes = collector._collect_top_processes()
        
        assert "by_cpu" in top_processes
        assert "by_mem" in top_processes
        assert len(top_processes["by_cpu"]) > 0
        assert len(top_processes["by_mem"]) > 0
        
        # Check first process (by CPU)
        first_process = top_processes["by_cpu"][0]
        assert first_process["pid"] == 1234
        assert first_process["cmd"] == "sshd"
        assert first_process["user"] == "root"
        assert first_process["cpu_pct"] == 5.0
        assert first_process["mem_pct"] == 2.0

class TestUSBCollector:
    """Test USB collector"""
    
    def test_init(self):
        """Test USB collector initialization"""
        collector = USBCollector()
        assert collector.timeout == 30
    
    @patch('agent.collectors.usb.subprocess.run')
    def test_collect_recent_usb_events(self, mock_run):
        """Test USB events collection"""
        # Mock lsusb command
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 002 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub
"""
        mock_run.return_value = mock_result
        
        collector = USBCollector()
        events = collector._collect_recent_usb_events()
        
        # Should return list (may be empty if no recent events)
        assert isinstance(events, list)
    
    def test_parse_lsusb_output(self):
        """Test lsusb output parsing"""
        collector = USBCollector()
        
        output = """
Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 002 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub
"""
        
        devices = collector._parse_lsusb_output(output)
        
        assert len(devices) == 2
        assert devices[0]["bus"] == "001"
        assert devices[0]["device"] == "002"
        assert devices[0]["vendor_id"] == "046d"
        assert devices[0]["product_id"] == "c52b"
        assert devices[0]["name"] == "Logitech, Inc. Unifying Receiver"
        
        assert devices[1]["vendor_id"] == "1d6b"
        assert devices[1]["product_id"] == "0001"
    
    def test_get_device_class(self):
        """Test device class detection"""
        collector = USBCollector()
        
        # Test known device classes
        assert collector._get_device_class("1d6b", "0001") == "hub"
        assert collector._get_device_class("046d", "c52b") == "keyboard"
        assert collector._get_device_class("045e", "0040") == "keyboard"
        
        # Test unknown device
        assert collector._get_device_class("1234", "5678") == "unknown"
    
    def test_monitor_usb_changes(self):
        """Test USB change monitoring"""
        collector = USBCollector()
        
        previous_devices = [
            {"vendor_id": "046d", "product_id": "c52b", "name": "Logitech Mouse"}
        ]
        
        current_devices = [
            {"vendor_id": "046d", "product_id": "c52b", "name": "Logitech Mouse"},
            {"vendor_id": "045e", "product_id": "0040", "name": "Microsoft Keyboard"}
        ]
        
        events = collector.monitor_usb_changes(previous_devices, current_devices)
        
        assert len(events) == 1  # One device added
        assert events[0]["action"] == "add"
        assert events[0]["vendor_id"] == "045e"
        assert events[0]["product_id"] == "0040"
