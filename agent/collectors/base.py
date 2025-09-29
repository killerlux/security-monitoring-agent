"""
Base collector class and utilities
"""

import subprocess
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class BaseCollector(ABC):
    """Base class for all collectors"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Collect data and return structured result"""
        pass
    
    def run_command(self, cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """Run command with timeout and error handling"""
        timeout = timeout or self.timeout
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with code {e.returncode}: {' '.join(cmd)}")
            logger.error(f"Error output: {e.stderr}")
            raise
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}")
            raise
    
    def safe_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Safely parse JSON with error handling"""
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return None
    
    def parse_int(self, value: str, default: int = 0) -> int:
        """Safely parse integer with default"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def parse_float(self, value: str, default: float = 0.0) -> float:
        """Safely parse float with default"""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    
    def get_file_content(self, path: str) -> Optional[str]:
        """Read file content safely"""
        try:
            file_path = Path(path)
            if file_path.exists():
                return file_path.read_text().strip()
            return None
        except (IOError, OSError) as e:
            logger.error(f"Failed to read file {path}: {e}")
            return None
