"""
System collector for CPU, memory, disk, and processes
"""

import os
import re
import subprocess
from typing import Dict, Any, List, Optional
from agent.collectors.base import BaseCollector

class SystemCollector(BaseCollector):
    """Collects system resource information"""
    
    def collect(self) -> Dict[str, Any]:
        """Collect all system information"""
        return {
            "cpu": self._collect_cpu_info(),
            "memory": self._collect_memory_info(),
            "disk": self._collect_disk_info(),
            "top_processes": self._collect_top_processes()
        }
    
    def _collect_cpu_info(self) -> Dict[str, float]:
        """Collect CPU load and usage information"""
        cpu_info = {
            "load1": 0.0,
            "load5": 0.0,
            "load15": 0.0,
            "user_pct": 0.0,
            "system_pct": 0.0,
            "iowait_pct": 0.0
        }
        
        try:
            # Get load average
            loadavg = self.get_file_content("/proc/loadavg")
            if loadavg:
                parts = loadavg.split()
                if len(parts) >= 3:
                    cpu_info["load1"] = self.parse_float(parts[0])
                    cpu_info["load5"] = self.parse_float(parts[1])
                    cpu_info["load15"] = self.parse_float(parts[2])
            
            # Get CPU usage from /proc/stat
            stat_content = self.get_file_content("/proc/stat")
            if stat_content:
                cpu_usage = self._parse_cpu_stat(stat_content)
                if cpu_usage:
                    cpu_info.update(cpu_usage)
        
        except Exception as e:
            logger.error(f"Failed to collect CPU info: {e}")
        
        return cpu_info
    
    def _parse_cpu_stat(self, stat_content: str) -> Optional[Dict[str, float]]:
        """Parse CPU statistics from /proc/stat"""
        lines = stat_content.split('\n')
        if not lines:
            return None
        
        # First line is overall CPU stats
        cpu_line = lines[0]
        parts = cpu_line.split()
        
        if len(parts) < 8:
            return None
        
        # Parse CPU times: user, nice, system, idle, iowait, irq, softirq, steal
        user = self.parse_int(parts[1])
        nice = self.parse_int(parts[2])
        system = self.parse_int(parts[3])
        idle = self.parse_int(parts[4])
        iowait = self.parse_int(parts[5])
        
        total = user + nice + system + idle + iowait
        
        if total == 0:
            return None
        
        return {
            "user_pct": (user + nice) * 100.0 / total,
            "system_pct": system * 100.0 / total,
            "iowait_pct": iowait * 100.0 / total
        }
    
    def _collect_memory_info(self) -> Dict[str, int]:
        """Collect memory information"""
        memory_info = {
            "total_mb": 0,
            "used_mb": 0,
            "free_mb": 0,
            "cached_mb": 0
        }
        
        try:
            # Try to use free command first
            result = self.run_command(["free", "-m"], timeout=10)
            memory_info = self._parse_free_output(result.stdout)
        
        except Exception as e:
            logger.error(f"Failed to collect memory info with free: {e}")
            
            # Fallback to /proc/meminfo
            try:
                meminfo = self.get_file_content("/proc/meminfo")
                if meminfo:
                    memory_info = self._parse_meminfo(meminfo)
            except Exception as e2:
                logger.error(f"Failed to collect memory info from /proc/meminfo: {e2}")
        
        return memory_info
    
    def _parse_free_output(self, output: str) -> Dict[str, int]:
        """Parse free command output"""
        memory_info = {
            "total_mb": 0,
            "used_mb": 0,
            "free_mb": 0,
            "cached_mb": 0
        }
        
        lines = output.split('\n')
        if len(lines) < 2:
            return memory_info
        
        # Parse memory line: Mem: total used free shared buff/cache available
        mem_line = lines[1]
        parts = mem_line.split()
        
        if len(parts) >= 7:
            memory_info["total_mb"] = self.parse_int(parts[1])
            memory_info["used_mb"] = self.parse_int(parts[2])
            memory_info["free_mb"] = self.parse_int(parts[3])
            # buff/cache is parts[5]
            memory_info["cached_mb"] = self.parse_int(parts[5])
        
        return memory_info
    
    def _parse_meminfo(self, meminfo_content: str) -> Dict[str, int]:
        """Parse /proc/meminfo content"""
        memory_info = {
            "total_mb": 0,
            "used_mb": 0,
            "free_mb": 0,
            "cached_mb": 0
        }
        
        lines = meminfo_content.split('\n')
        
        for line in lines:
            if ':' not in line:
                continue
            
            key, value = line.split(':', 1)
            value = value.strip().split()[0]
            
            if key == "MemTotal":
                memory_info["total_mb"] = self.parse_int(value) // 1024  # Convert kB to MB
            elif key == "MemFree":
                memory_info["free_mb"] = self.parse_int(value) // 1024
            elif key == "Cached":
                memory_info["cached_mb"] = self.parse_int(value) // 1024
        
        # Calculate used memory
        memory_info["used_mb"] = memory_info["total_mb"] - memory_info["free_mb"]
        
        return memory_info
    
    def _collect_disk_info(self) -> List[Dict[str, Any]]:
        """Collect disk usage information"""
        disks = []
        
        try:
            # Use df command
            result = self.run_command(["df", "-hT"], timeout=15)
            disks = self._parse_df_output(result.stdout)
        
        except Exception as e:
            logger.error(f"Failed to collect disk info: {e}")
        
        return disks
    
    def _parse_df_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse df command output"""
        disks = []
        
        lines = output.split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 7:
                continue
            
            mount = parts[6]
            fs = parts[1]
            
            # Skip special filesystems
            if mount in ["/proc", "/sys", "/dev", "/run", "/tmp"]:
                continue
            
            # Parse size (remove 'G' suffix and convert to float)
            size_str = parts[2].replace('G', '').replace('M', '')
            used_str = parts[3].replace('G', '').replace('M', '')
            
            size_gb = self.parse_float(size_str)
            used_gb = self.parse_float(used_str)
            
            # Convert MB to GB if needed
            if 'M' in parts[2]:
                size_gb = size_gb / 1024
            if 'M' in parts[3]:
                used_gb = used_gb / 1024
            
            # Parse percentage
            pct_str = parts[4].replace('%', '')
            used_pct = self.parse_float(pct_str)
            
            disks.append({
                "mount": mount,
                "fs": fs,
                "size_gb": size_gb,
                "used_gb": used_gb,
                "used_pct": used_pct,
                "inodes_pct": 0.0  # Would need separate df -i command
            })
        
        return disks
    
    def _collect_top_processes(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect top processes by CPU and memory"""
        top_processes = {
            "by_cpu": [],
            "by_mem": []
        }
        
        try:
            # Use ps command to get process info
            result = self.run_command([
                "ps", "aux", "--sort=-%cpu", "--no-headers"
            ], timeout=15)
            
            processes = self._parse_ps_output(result.stdout)
            
            # Sort by CPU and memory
            top_processes["by_cpu"] = sorted(
                processes, 
                key=lambda x: x["cpu_pct"], 
                reverse=True
            )[:10]
            
            top_processes["by_mem"] = sorted(
                processes, 
                key=lambda x: x["mem_pct"], 
                reverse=True
            )[:10]
        
        except Exception as e:
            logger.error(f"Failed to collect top processes: {e}")
        
        return top_processes
    
    def _parse_ps_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ps command output"""
        processes = []
        
        lines = output.split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 11:
                continue
            
            try:
                # ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                user = parts[0]
                pid = self.parse_int(parts[1])
                cpu_pct = self.parse_float(parts[2])
                mem_pct = self.parse_float(parts[3])
                
                # Command is everything from index 10 onwards
                cmd = ' '.join(parts[10:])
                
                processes.append({
                    "pid": pid,
                    "cmd": cmd[:100],  # Limit command length
                    "user": user,
                    "cpu_pct": cpu_pct,
                    "mem_pct": mem_pct
                })
            
            except (ValueError, IndexError):
                continue
        
        return processes
