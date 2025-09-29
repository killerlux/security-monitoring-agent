import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import csv

logger = logging.getLogger(__name__)

class StateExporter:
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", True)
        self.export_dir = Path(config.get("dir", "exports/states"))
        self.compression = config.get("compression", "gzip")
        self.retention_days = config.get("retention_days", 30)
        self.write_latest = config.get("write_latest", True)
        self.write_manifest = config.get("write_manifest", True)
        self.timezone = config.get("timezone", "UTC")
        
        # Ensure export directory exists
        self.export_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"StateExporter initialized: enabled={self.enabled}, dir={self.export_dir}")

    def export_state(self, full_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Export minimal state to timestamped compressed file"""
        if not self.enabled:
            logger.debug("Export disabled, skipping")
            return None
            
        try:
            # Parse timestamp
            timestamp_str = full_result["timestamp"]
            if isinstance(timestamp_str, str):
                if "T" in timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                else:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                timestamp = timestamp_str
                
            # Ensure UTC
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                timestamp = timestamp.astimezone(timezone.utc)
            
            # Create directory structure: exports/states/{YYYY}/{MM}/{DD}/{host}/
            host = full_result["host"]
            year = timestamp.strftime("%Y")
            month = timestamp.strftime("%M")
            day = timestamp.strftime("%d")
            
            export_path = self.export_dir / year / month / day / host
            export_path.mkdir(parents=True, exist_ok=True)
            
            # Serialize minimal state
            minimal_state = self._serialize_minimal_state(full_result, timestamp)
            
            # Generate filename: state-{host}-{YYYYMMDD}-{HHmmss}-{runId}.jsonl.gz
            filename = f"state-{host}-{timestamp.strftime('%Y%m%d')}-{timestamp.strftime('%H%M%S')}-{full_result['run_id']}.jsonl.gz"
            file_path = export_path / filename
            
            # Write compressed file
            self._write_jsonl_gz(file_path, minimal_state)
            
            # Update latest.json
            if self.write_latest:
                latest_path = export_path / "latest.json"
                self._update_latest(latest_path, minimal_state)
            
            # Append to manifest
            if self.write_manifest:
                manifest_path = export_path / "manifest.csv"
                self._append_manifest(manifest_path, {
                    "ts": timestamp.isoformat(),
                    "host": host,
                    "run_id": full_result["run_id"],
                    "path": str(file_path.relative_to(self.export_dir)),
                    "size_bytes": file_path.stat().st_size,
                    "alerts_count": len(full_result.get("alerts", []))
                })
            
            logger.info(f"State exported: {file_path} ({file_path.stat().st_size} bytes)")
            
            return {
                "path": str(file_path),
                "size_bytes": file_path.stat().st_size,
                "timestamp": timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to export state: {e}")
            return None

    def _ensure_dirs(self, timestamp: datetime, host: str) -> Path:
        """Ensure directory structure exists"""
        year = timestamp.strftime("%Y")
        month = timestamp.strftime("%M")
        day = timestamp.strftime("%d")
        
        export_path = self.export_dir / year / month / day / host
        export_path.mkdir(parents=True, exist_ok=True)
        return export_path

    def _serialize_minimal_state(self, full_result: Dict[str, Any], timestamp: datetime) -> Dict[str, Any]:
        """Create minimal state projection"""
        # Extract CPU data
        cpu_data = full_result.get("cpu", {})
        cpu = {
            "load1": cpu_data.get("load1", 0.0),
            "load5": cpu_data.get("load5", 0.0),
            "load15": cpu_data.get("load15", 0.0),
            "user_pct": cpu_data.get("user_pct", 0),
            "system_pct": cpu_data.get("system_pct", 0),
            "iowait_pct": cpu_data.get("iowait_pct", 0)
        }
        
        # Extract memory data
        mem_data = full_result.get("memory", {})
        mem = {
            "used_mb": mem_data.get("used_mb", 0),
            "total_mb": mem_data.get("total_mb", 0)
        }
        
        # Extract disk data
        disk_data = full_result.get("disk", [])
        disk = []
        for d in disk_data:
            disk.append({
                "mount": d.get("mount", "/"),
                "used_pct": d.get("used_pct", 0.0)
            })
        
        # Extract network data
        net_data = full_result.get("network", {})
        default_iface = net_data.get("default_interface")
        
        ifaces = []
        for iface in net_data.get("interfaces", []):
            ifaces.append({
                "name": iface.get("name", ""),
                "state": iface.get("state", "unknown"),
                "rx_delta": iface.get("rx_delta", 0),
                "tx_delta": iface.get("tx_delta", 0)
            })
        
        open_ports = []
        for port in net_data.get("open_ports", []):
            open_ports.append({
                "proto": port.get("protocol", "tcp"),
                "port": port.get("port", 0),
                "proc": port.get("process", "")
            })
        
        attempts = net_data.get("connection_attempts", {})
        attempts_minimal = {
            "icmp": attempts.get("icmp", 0),
            "ssh_fail": attempts.get("ssh_fail", 0),
            "telnet_fail": attempts.get("telnet_fail", 0)
        }
        
        # Extract alerts
        alerts = []
        for alert in full_result.get("alerts", []):
            alerts.append({
                "severity": alert.get("severity", "info"),
                "code": alert.get("code", "UNKNOWN")
            })
        
        return {
            "ts": timestamp.isoformat(),
            "host": full_result["host"],
            "run_id": full_result["run_id"],
            "cpu": cpu,
            "mem": mem,
            "disk": disk,
            "net": {
                "default_iface": default_iface,
                "ifaces": ifaces,
                "open_ports": open_ports,
                "attempts": attempts_minimal
            },
            "alerts": alerts
        }

    def _write_jsonl_gz(self, path: Path, doc: Dict[str, Any]) -> None:
        """Write document as compressed JSON Lines"""
        with gzip.open(path, 'wt', encoding='utf-8') as f:
            json.dump(doc, f, ensure_ascii=False, separators=(',', ':'))
            f.write('\n')

    def _update_latest(self, path: Path, doc: Dict[str, Any]) -> None:
        """Update latest.json atomically"""
        temp_path = path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        shutil.move(str(temp_path), str(path))

    def _append_manifest(self, path: Path, row: Dict[str, Any]) -> None:
        """Append row to manifest CSV"""
        file_exists = path.exists()
        
        with open(path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ts', 'host', 'run_id', 'path', 'size_bytes', 'alerts_count'])
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

    def apply_retention(self) -> int:
        """Apply retention policy, delete old exports"""
        if not self.export_dir.exists():
            return 0
            
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        deleted_count = 0
        
        for year_dir in self.export_dir.iterdir():
            if not year_dir.is_dir():
                continue
                
            for month_dir in year_dir.iterdir():
                if not month_dir.is_dir():
                    continue
                    
                for day_dir in month_dir.iterdir():
                    if not day_dir.is_dir():
                        continue
                        
                    try:
                        # Check if this day is older than retention period
                        day_date = datetime.strptime(f"{year_dir.name}{month_dir.name}{day_dir.name}", "%Y%m%d")
                        day_date = day_date.replace(tzinfo=timezone.utc)
                        
                        if day_date < cutoff_date:
                            shutil.rmtree(day_dir)
                            deleted_count += 1
                            logger.info(f"Deleted old export directory: {day_dir}")
                    except ValueError:
                        # Skip invalid date directories
                        continue
        
        return deleted_count

    def get_export_stats(self) -> Dict[str, Any]:
        """Get export statistics"""
        if not self.export_dir.exists():
            return {"total_exports": 0, "total_size_bytes": 0, "hosts": [], "days": 0}
        
        total_exports = 0
        total_size = 0
        hosts = set()
        days = set()
        
        for year_dir in self.export_dir.iterdir():
            if not year_dir.is_dir():
                continue
                
            for month_dir in year_dir.iterdir():
                if not month_dir.is_dir():
                    continue
                    
                for day_dir in month_dir.iterdir():
                    if not day_dir.is_dir():
                        continue
                        
                    days.add(f"{year_dir.name}-{month_dir.name}-{day_dir.name}")
                    
                    for host_dir in day_dir.iterdir():
                        if not host_dir.is_dir():
                            continue
                            
                        hosts.add(host_dir.name)
                        
                        for file_path in host_dir.glob("*.jsonl.gz"):
                            total_exports += 1
                            total_size += file_path.stat().st_size
        
        return {
            "total_exports": total_exports,
            "total_size_bytes": total_size,
            "hosts": list(hosts),
            "days": len(days)
        }

    def get_latest_state(self, host: str) -> Optional[Dict[str, Any]]:
        """Get latest state for a host"""
        if not self.export_dir.exists():
            return None
            
        # Find the most recent latest.json file for this host
        latest_files = list(self.export_dir.rglob(f"**/{host}/latest.json"))
        
        if not latest_files:
            return None
            
        # Sort by modification time, get the most recent
        latest_file = max(latest_files, key=lambda p: p.stat().st_mtime)
        
        try:
            with open(latest_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read latest state for {host}: {e}")
            return None

    def get_history(self, host: str, from_ts: Optional[datetime] = None, to_ts: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get historical data for a host"""
        if not self.export_dir.exists():
            return []
            
        history = []
        
        # Find all export files for this host
        export_files = list(self.export_dir.rglob(f"**/{host}/state-*.jsonl.gz"))
        
        for file_path in sorted(export_files):
            try:
                # Parse timestamp from filename
                filename = file_path.name
                # Format: state-{host}-{YYYYMMDD}-{HHmmss}-{runId}.jsonl.gz
                parts = filename.split('-')
                if len(parts) >= 4:
                    date_str = parts[2] + parts[3][:6]  # YYYYMMDDHHmmss
                    file_timestamp = datetime.strptime(date_str, "%Y%m%d%H%M%S")
                    file_timestamp = file_timestamp.replace(tzinfo=timezone.utc)
                    
                    # Apply time filters
                    if from_ts and file_timestamp < from_ts:
                        continue
                    if to_ts and file_timestamp > to_ts:
                        continue
                    
                    # Read the file
                    with gzip.open(file_path, 'rt') as f:
                        content = f.read().strip()
                        if content:
                            data = json.loads(content)
                            history.append(data)
                            
            except Exception as e:
                logger.warning(f"Failed to read history file {file_path}: {e}")
                continue
        
        # Sort by timestamp
        history.sort(key=lambda x: x.get('ts', ''))
        return history
