"""
JSON Schema and Pydantic models for Security Monitoring Agent
Compliant with JSON Schema Draft 2020-12
"""

import json
from datetime import datetime
from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field, field_validator
from uuid import uuid4

# JSON Schema Definition
MONITORING_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://security-monitor.local/schemas/monitoring-output.json",
    "title": "Security Monitoring Agent Output",
    "description": "Output format for Linux security monitoring agent",
    "type": "object",
    "properties": {
        "timestamp": {
            "type": "string",
            "format": "date-time",
            "description": "RFC3339 timestamp of the monitoring run"
        },
        "host": {
            "type": "string",
            "description": "Hostname of the monitored system"
        },
        "run_id": {
            "type": "string",
            "format": "uuid",
            "description": "Unique identifier for this monitoring run"
        },
        "network": {
            "$ref": "#/$defs/network"
        },
        "system": {
            "$ref": "#/$defs/system"
        },
        "usb": {
            "$ref": "#/$defs/usb"
        },
        "appsec": {
            "$ref": "#/$defs/appsec"
        },
        "diff": {
            "$ref": "#/$defs/diff"
        }
    },
    "required": ["timestamp", "host", "run_id", "network", "system", "usb", "appsec", "diff"],
    "$defs": {
        "network": {
            "type": "object",
            "properties": {
                "open_ports": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/port"}
                },
                "services": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/service"}
                },
                "interfaces": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/interface"}
                },
                "connections": {
                    "$ref": "#/$defs/connections"
                },
                "policy": {
                    "$ref": "#/$defs/network_policy"
                }
            },
            "required": ["open_ports", "services", "interfaces", "connections", "policy"]
        },
        "port": {
            "type": "object",
            "properties": {
                "proto": {"type": "string", "enum": ["tcp", "udp"]},
                "port": {"type": "integer", "minimum": 0, "maximum": 65535},
                "process": {"type": "string"},
                "pid": {"type": "integer", "minimum": 0},
                "listen_addr": {"type": "string"},
                "state": {"type": "string", "enum": ["LISTEN", "ESTABLISHED", "TIME_WAIT", "OTHER"]}
            },
            "required": ["proto", "port", "process", "pid", "listen_addr", "state"]
        },
        "service": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "active": {"type": "boolean"},
                "enabled": {"type": "boolean"},
                "version": {"type": ["string", "null"]},
                "port": {"type": "integer"},
                "risk": {"type": "string", "enum": ["low", "medium", "high"]}
            },
            "required": ["name", "active", "enabled", "version", "port", "risk"]
        },
        "interface": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "type": {"type": "string", "enum": ["ethernet", "wifi", "virtual"]},
                "state": {"type": "string", "enum": ["up", "down"]},
                "ipv4": {"type": ["string", "null"]},
                "ipv6": {"type": ["string", "null"]},
                "mac": {"type": "string"},
                "default_route": {"type": "boolean"},
                "speed_mbps": {"type": "integer"},
                "ssid": {"type": ["string", "null"]},
                "signal_dbm": {"type": "integer"},
                "rx_bytes": {"type": "integer"},
                "tx_bytes": {"type": "integer"},
                "rx_delta": {"type": "integer"},
                "tx_delta": {"type": "integer"}
            },
            "required": ["name", "type", "state", "ipv4", "ipv6", "mac", "default_route", 
                        "speed_mbps", "ssid", "signal_dbm", "rx_bytes", "tx_bytes", "rx_delta", "tx_delta"]
        },
        "connections": {
            "type": "object",
            "properties": {
                "by_state": {
                    "type": "object",
                    "properties": {
                        "ESTABLISHED": {"type": "integer"},
                        "TIME_WAIT": {"type": "integer"},
                        "LISTEN": {"type": "integer"},
                        "OTHER": {"type": "integer"}
                    }
                },
                "attempts": {
                    "type": "object",
                    "properties": {
                        "icmp": {"type": "integer"},
                        "ssh": {
                            "type": "object",
                            "properties": {
                                "success": {"type": "integer"},
                                "fail": {"type": "integer"}
                            }
                        },
                        "telnet": {
                            "type": "object",
                            "properties": {
                                "success": {"type": "integer"},
                                "fail": {"type": "integer"}
                            }
                        }
                    }
                }
            }
        },
        "network_policy": {
            "type": "object",
            "properties": {
                "wifi_enabled": {"type": "boolean"},
                "should_disable_wifi": {"type": "boolean"}
            }
        },
        "system": {
            "type": "object",
            "properties": {
                "cpu": {"$ref": "#/$defs/cpu"},
                "memory": {"$ref": "#/$defs/memory"},
                "disk": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/disk"}
                },
                "top_processes": {"$ref": "#/$defs/top_processes"}
            }
        },
        "cpu": {
            "type": "object",
            "properties": {
                "load1": {"type": "number"},
                "load5": {"type": "number"},
                "load15": {"type": "number"},
                "user_pct": {"type": "number"},
                "system_pct": {"type": "number"},
                "iowait_pct": {"type": "number"}
            }
        },
        "memory": {
            "type": "object",
            "properties": {
                "total_mb": {"type": "integer"},
                "used_mb": {"type": "integer"},
                "free_mb": {"type": "integer"},
                "cached_mb": {"type": "integer"}
            }
        },
        "disk": {
            "type": "object",
            "properties": {
                "mount": {"type": "string"},
                "fs": {"type": "string"},
                "size_gb": {"type": "number"},
                "used_gb": {"type": "number"},
                "used_pct": {"type": "number"},
                "inodes_pct": {"type": "number"}
            }
        },
        "top_processes": {
            "type": "object",
            "properties": {
                "by_cpu": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/process"}
                },
                "by_mem": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/process"}
                }
            }
        },
        "process": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "cmd": {"type": "string"},
                "user": {"type": "string"},
                "cpu_pct": {"type": "number"},
                "mem_pct": {"type": "number"}
            }
        },
        "usb": {
            "type": "object",
            "properties": {
                "recent_events": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/usb_event"}
                }
            }
        },
        "usb_event": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["add", "remove"]},
                "time": {"type": "string", "format": "date-time"},
                "device": {"type": "string"},
                "vendor_id": {"type": "string"},
                "product_id": {"type": "string"},
                "class_name": {"type": "string"}
            }
        },
        "appsec": {
            "type": "object",
            "properties": {
                "http_checks": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/http_check"}
                },
                "sbom": {"$ref": "#/$defs/sbom"},
                "dast": {"$ref": "#/$defs/dast"},
                "policies": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/policy_result"}
                }
            }
        },
        "http_check": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "hsts": {"type": "boolean"},
                "tls_version": {"type": "string"},
                "csp": {"type": "string", "enum": ["present", "missing"]},
                "cookies_secure": {"type": "boolean"},
                "findings": {"type": "array", "items": {"type": "string"}}
            }
        },
        "sbom": {
            "type": "object",
            "properties": {
                "format": {"type": "string"},
                "components": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/sbom_component"}
                }
            }
        },
        "sbom_component": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "cves": {"type": "array", "items": {"type": "string"}}
            }
        },
        "dast": {
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "issues": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/dast_issue"}
                }
            }
        },
        "dast_issue": {
            "type": "object",
            "properties": {
                "risk": {"type": "string", "enum": ["low", "medium", "high"]},
                "rule": {"type": "string"},
                "url": {"type": "string"}
            }
        },
        "policy_result": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "status": {"type": "string", "enum": ["pass", "fail"]},
                "evidence": {"type": "object"}
            }
        },
        "diff": {
            "type": "object",
            "properties": {
                "new_open_ports": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"proto": {"type": "string"}, "port": {"type": "integer"}}}
                },
                "closed_ports": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"proto": {"type": "string"}, "port": {"type": "integer"}}}
                },
                "service_state_changes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "from": {"type": "string"},
                            "to": {"type": "string"}
                        }
                    }
                },
                "alerts": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/alert"}
                }
            }
        },
        "alert": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["info", "warn", "high"]},
                "code": {"type": "string"},
                "message": {"type": "string"},
                "evidence": {"type": "object"}
            }
        }
    }
}

# Pydantic Models
class Port(BaseModel):
    proto: Literal["tcp", "udp"]
    port: int = Field(..., ge=0, le=65535)
    process: str
    pid: int = Field(..., ge=0)
    listen_addr: str
    state: Literal["LISTEN", "ESTABLISHED", "TIME_WAIT", "OTHER"]

class Service(BaseModel):
    name: str
    active: bool
    enabled: bool
    version: Optional[str]
    port: int
    risk: Literal["low", "medium", "high"]

class Interface(BaseModel):
    name: str
    type: Literal["ethernet", "wifi", "virtual"]
    state: Literal["up", "down"]
    ipv4: Optional[str]
    ipv6: Optional[str]
    mac: str
    default_route: bool
    speed_mbps: int
    ssid: Optional[str]
    signal_dbm: int
    rx_bytes: int
    tx_bytes: int
    rx_delta: int
    tx_delta: int

class ConnectionAttempts(BaseModel):
    success: int = 0
    fail: int = 0

class Connections(BaseModel):
    by_state: Dict[str, int]
    attempts: Dict[str, Any]  # Can be int or ConnectionAttempts

class NetworkPolicy(BaseModel):
    wifi_enabled: bool
    should_disable_wifi: bool

class Network(BaseModel):
    open_ports: List[Port]
    services: List[Service]
    interfaces: List[Interface]
    connections: Connections
    policy: NetworkPolicy

class CPU(BaseModel):
    load1: float
    load5: float
    load15: float
    user_pct: float
    system_pct: float
    iowait_pct: float

class Memory(BaseModel):
    total_mb: int
    used_mb: int
    free_mb: int
    cached_mb: int

class Disk(BaseModel):
    mount: str
    fs: str
    size_gb: float
    used_gb: float
    used_pct: float
    inodes_pct: float

class Process(BaseModel):
    pid: int
    cmd: str
    user: str
    cpu_pct: float
    mem_pct: float

class TopProcesses(BaseModel):
    by_cpu: List[Process]
    by_mem: List[Process]

class System(BaseModel):
    cpu: CPU
    memory: Memory
    disk: List[Disk]
    top_processes: TopProcesses

class USBEvent(BaseModel):
    action: Literal["add", "remove"]
    time: datetime
    device: str
    vendor_id: str
    product_id: str
    class_name: str  # 'class' is a reserved keyword in Python

class USB(BaseModel):
    recent_events: List[USBEvent]

class HTTPCheck(BaseModel):
    target: str
    hsts: bool
    tls_version: str
    csp: Literal["present", "missing"]
    cookies_secure: bool
    findings: List[str]

class SBOMComponent(BaseModel):
    name: str
    version: str
    cves: List[str]

class SBOM(BaseModel):
    format: str
    components: List[SBOMComponent]

class DASTIssue(BaseModel):
    risk: Literal["low", "medium", "high"]
    rule: str
    url: str

class DAST(BaseModel):
    tool: str
    issues: List[DASTIssue]

class PolicyResult(BaseModel):
    id: str
    status: Literal["pass", "fail"]
    evidence: Dict[str, Any]

class AppSec(BaseModel):
    http_checks: List[HTTPCheck]
    sbom: SBOM
    dast: DAST
    policies: List[PolicyResult]

class Alert(BaseModel):
    severity: Literal["info", "warn", "high"]
    code: str
    message: str
    evidence: Dict[str, Any]

class Diff(BaseModel):
    new_open_ports: List[Dict[str, Any]]
    closed_ports: List[Dict[str, Any]]
    service_state_changes: List[Dict[str, str]]
    alerts: List[Alert]

class MonitoringOutput(BaseModel):
    timestamp: datetime
    host: str
    run_id: str
    network: Network
    system: System
    usb: USB
    appsec: AppSec
    diff: Diff

    @field_validator('run_id', mode='before')
    @classmethod
    def generate_run_id(cls, v):
        return str(uuid4()) if v is None else v

    @field_validator('timestamp', mode='before')
    @classmethod
    def set_timestamp(cls, v):
        return datetime.now() if v is None else v

def save_schema(path: str = "/home/aymen/Bureau/esaip/gerersecu/monitoring/agent/models/monitoring-schema.json"):
    """Save JSON Schema to file"""
    with open(path, 'w') as f:
        json.dump(MONITORING_SCHEMA, f, indent=2)

def create_example_output() -> MonitoringOutput:
    """Create a realistic example output for testing"""
    return MonitoringOutput(
        timestamp=datetime.now(),
        host="security-monitor.local",
        run_id=str(uuid4()),
        network=Network(
            open_ports=[
                Port(proto="tcp", port=22, process="sshd", pid=1234, listen_addr="0.0.0.0", state="LISTEN"),
                Port(proto="tcp", port=80, process="nginx", pid=5678, listen_addr="127.0.0.1", state="LISTEN")
            ],
            services=[
                Service(name="ssh", active=True, enabled=True, version="OpenSSH_8.2p1", port=22, risk="low"),
                Service(name="http", active=True, enabled=True, version="nginx/1.18.0", port=80, risk="medium")
            ],
            interfaces=[
                Interface(
                    name="eth0", type="ethernet", state="up",
                    ipv4="192.168.1.100", ipv6="::1", mac="aa:bb:cc:dd:ee:ff",
                    default_route=True, speed_mbps=1000, ssid=None, signal_dbm=0,
                    rx_bytes=1024000, tx_bytes=512000, rx_delta=1024, tx_delta=512
                )
            ],
            connections=Connections(
                by_state={"ESTABLISHED": 15, "TIME_WAIT": 3, "LISTEN": 8, "OTHER": 2},
                attempts={"icmp": 150, "ssh": {"success": 5, "fail": 2}, "telnet": {"success": 0, "fail": 0}}
            ),
            policy=NetworkPolicy(wifi_enabled=False, should_disable_wifi=True)
        ),
        system=System(
            cpu=CPU(load1=0.5, load5=0.8, load15=1.2, user_pct=25.0, system_pct=10.0, iowait_pct=5.0),
            memory=Memory(total_mb=8192, used_mb=4096, free_mb=4096, cached_mb=1024),
            disk=[
                Disk(mount="/", fs="ext4", size_gb=100.0, used_gb=45.0, used_pct=45.0, inodes_pct=15.0)
            ],
            top_processes=TopProcesses(
                by_cpu=[Process(pid=1234, cmd="sshd", user="root", cpu_pct=5.0, mem_pct=2.0)],
                by_mem=[Process(pid=5678, cmd="nginx", user="www-data", cpu_pct=1.0, mem_pct=8.0)]
            )
        ),
        usb=USB(recent_events=[]),
        appsec=AppSec(
            http_checks=[
                HTTPCheck(
                    target="https://localhost",
                    hsts=True,
                    tls_version="TLS1.3",
                    csp="present",
                    cookies_secure=True,
                    findings=[]
                )
            ],
            sbom=SBOM(
                format="CycloneDX",
                components=[
                    SBOMComponent(name="openssl", version="1.1.1w", cves=["CVE-2023-0286"])
                ]
            ),
            dast=DAST(tool="zap", issues=[]),
            policies=[
                PolicyResult(id="POL_HTTP_TLS", status="pass", evidence={"target": "https://localhost"})
            ]
        ),
        diff=Diff(
            new_open_ports=[],
            closed_ports=[],
            service_state_changes=[],
            alerts=[
                Alert(
                    severity="info",
                    code="POLICY_WIFI_DISABLED",
                    message="Wi-Fi désactivé conformément à la politique",
                    evidence={"policy": "wifi_disabled"}
                )
            ]
        )
    )

if __name__ == "__main__":
    # Save schema
    save_schema()
    
    # Create and save example
    example = create_example_output()
    with open("/home/aymen/Bureau/esaip/gerersecu/monitoring/agent/models/example-output.json", 'w') as f:
        json.dump(example.model_dump(), f, indent=2, default=str)
    
    print("✅ JSON Schema and example created successfully!")
