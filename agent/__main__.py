#!/usr/bin/env python3
"""
Main entry point for Security Monitoring Agent
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from agent.collectors.manager import CollectorManager
from agent.state.manager import StateManager
from agent.models.schema import MonitoringOutput, save_schema, create_example_output

def main():
    parser = argparse.ArgumentParser(description="Security Monitoring Agent")
    parser.add_argument("--collect", action="store_true", help="Run collection cycle")
    parser.add_argument("--schema", action="store_true", help="Generate JSON schema")
    parser.add_argument("--example", action="store_true", help="Generate example output")
    parser.add_argument("--test", action="store_true", help="Run test collection")
    parser.add_argument("--output", "-o", default="/var/lib/security-monitor", 
                       help="Output directory for logs and state")
    parser.add_argument("--config", "-c", default="config/policies.yaml",
                       help="Path to configuration file")
    
    args = parser.parse_args()
    
    if args.schema:
        save_schema()
        print("✅ JSON Schema generated")
        return 0
    
    if args.example:
        example = create_example_output()
        output_file = Path(args.output) / "example-output.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(example.model_dump(), f, indent=2, default=str)
        
        print(f"✅ Example output saved to {output_file}")
        return 0
    
    if args.test:
        try:
            # Run a quick test collection
            print("🧪 Running test collection...")
            state_manager = StateManager(args.output)
            collector_manager = CollectorManager(args.config, state_manager)
            
            result = collector_manager.collect_all()
            
            print("✅ Test collection completed successfully")
            print(f"📊 Collected data:")
            print(f"  - Host: {result.host}")
            print(f"  - Network ports: {len(result.network.open_ports)}")
            print(f"  - System load: {result.system.cpu.load1:.2f}")
            print(f"  - Alerts: {len(result.diff.alerts)}")
            
            return 0
            
        except Exception as e:
            print(f"❌ Test collection failed: {e}")
            return 1
    
    if args.collect:
        try:
            # Initialize managers
            state_manager = StateManager(args.output)
            collector_manager = CollectorManager(args.config, state_manager)
            
            # Run collection
            print(f"🔍 Starting monitoring collection at {datetime.now()}")
            result = collector_manager.collect_all()
            
            # Save results
            output_file = Path(args.output) / f"monitoring-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(result.model_dump(), f, indent=2, default=str)
            
            print(f"✅ Collection completed, results saved to {output_file}")
            
            # Print summary
            alert_count = len([a for a in result.diff.alerts if a.severity in ["warn", "high"]])
            if alert_count > 0:
                print(f"⚠️  {alert_count} alerts generated")
                for alert in result.diff.alerts:
                    if alert.severity in ["warn", "high"]:
                        print(f"  {alert.severity.upper()}: {alert.message}")
            else:
                print("✅ No critical alerts")
            
            return 0
            
        except Exception as e:
            print(f"❌ Collection failed: {e}")
            return 1
    
    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())
