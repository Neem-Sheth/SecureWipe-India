"""
SecureWipe India - Command Line Interface
CLI for automated and script-based operations
"""

import sys
import os
import json
import argparse
import logging
from typing import Optional
from pathlib import Path

# Attempt robust imports: prefer package-style 'src.*' imports when the
# project is executed as a package (for example via main.py), but fall
# back to local imports to support running this file directly.
try:
    from src.core.engine import SecureWipeEngine, WipeLevel, WipeResult
    from src.utils.logger import setup_logger
except Exception:
    try:
        # Fallback for environments where src is on sys.path
        from core.engine import SecureWipeEngine, WipeLevel, WipeResult
        from utils.logger import setup_logger
    except Exception as e:
        print(f"Import error: {e}")
        print("Make sure you're running from the project root or via main.py")
        sys.exit(1)

class SecureWipeCLI:
    """Command line interface for SecureWipe India"""
    
    def __init__(self):
        self.engine = None
        self.logger = None
        
    def run(self, args):
        """Main CLI entry point"""
        try:
            # Setup logging
            self.logger = setup_logger(__name__, level=logging.INFO if not args.quiet else logging.WARNING)
            
            # Initialize engine
            config_path = args.config if args.config else "config/settings.json"
            self.engine = SecureWipeEngine(config_path)
            
            # Execute command
            if args.command == "list":
                return self.list_devices(args)
            elif args.command == "analyze":
                return self.analyze_device(args)
            elif args.command == "wipe":
                return self.wipe_device(args)
            elif args.command == "verify":
                return self.verify_certificate(args)
            else:
                print(f"Unknown command: {args.command}")
                return 1
                
        except Exception as e:
            print(f"Error: {e}")
            if hasattr(args, 'debug') and args.debug:
                import traceback
                traceback.print_exc()
            return 1
    
    def list_devices(self, args) -> int:
        """List all storage devices"""
        try:
            print("Scanning for storage devices...")
            devices = self.engine.detect_storage_devices()
            
            if not devices:
                print("No storage devices found.")
                return 0
            
            # Output format
            if args.json:
                print(json.dumps(devices, indent=2, default=str))
            else:
                print(f"\\nFound {len(devices)} storage devices:\\n")
                print(f"{'Device':<20} {'Size (GB)':<12} {'Type':<15} {'Mount Point':<20}")
                print("-" * 70)
                
                for device in devices:
                    size_gb = device.get('size_gb', 0)
                    size_str = f"{size_gb:.2f}" if size_gb > 0 else "Unknown"
                    
                    print(f"{device['path']:<20} {size_str:<12} {device.get('device_type', 'unknown'):<15} {device.get('mount_point', 'None'):<20}")
            
            return 0
            
        except Exception as e:
            print(f"Failed to list devices: {e}")
            return 1
    
    def analyze_device(self, args) -> int:
        """Analyze a specific device"""
        try:
            if not args.device:
                print("Device path is required for analysis")
                return 1
            
            print(f"Analyzing device: {args.device}")
            analysis = self.engine.analyze_device(args.device)
            
            if args.json:
                print(json.dumps(analysis, indent=2, default=str))
            else:
                self._print_device_analysis(analysis)
            
            return 0
            
        except Exception as e:
            print(f"Device analysis failed: {e}")
            return 1
    
    def wipe_device(self, args) -> int:
        """Wipe a storage device"""
        try:
            if not args.device:
                print("Device path is required for wiping")
                return 1
            
            # Parse wipe level
            wipe_level = WipeLevel(args.level.lower())
            
            # Confirmation check
            if not args.force:
                if not self._confirm_wipe(args.device, wipe_level):
                    print("Operation cancelled.")
                    return 0
            
            # Progress callback
            def progress_callback(percentage):
                if not args.quiet:
                    print(f"\\rProgress: {percentage:.1f}%", end="", flush=True)
            
            print(f"Starting {wipe_level.value} wipe on {args.device}")
            
            # Execute wipe
            result = self.engine.wipe_device(args.device, wipe_level, progress_callback)
            
            if not args.quiet:
                print()  # New line after progress
            
            # Output results
            if result.success:
                print(f"✅ Wipe completed successfully!")
                print(f"   Duration: {result.duration_seconds:.1f} seconds")
                print(f"   Verification: {result.verification_passes} passes")
                if result.certificate_path:
                    print(f"   Certificate: {result.certificate_path}")
                return 0
            else:
                print(f"❌ Wipe failed: {result.error_message}")
                return 1
                
        except ValueError as e:
            print(f"Invalid wipe level. Use: clear, purge, or destroy")
            return 1
        except Exception as e:
            print(f"Wipe operation failed: {e}")
            return 1
    
    def verify_certificate(self, args) -> int:
        """Verify a certificate"""
        try:
            if not args.certificate:
                print("Certificate path is required for verification")
                return 1
            
            # Load certificate
            cert_path = Path(args.certificate)
            if not cert_path.exists():
                print(f"Certificate file not found: {cert_path}")
                return 1
            
            # For now, just validate JSON structure
            with open(cert_path, 'r') as f:
                cert_data = json.load(f)
            
            # Basic validation
            required_fields = ['certificate_id', 'device', 'wipe_operation', 'compliance']
            missing_fields = [field for field in required_fields if field not in cert_data]
            
            if missing_fields:
                print(f"❌ Invalid certificate: missing fields {missing_fields}")
                return 1
            
            print("✅ Certificate validation passed")
            print(f"   Certificate ID: {cert_data['certificate_id']}")
            print(f"   Device: {cert_data['device']['path']}")
            print(f"   Wipe Level: {cert_data['wipe_operation']['level']}")
            print(f"   Generated: {cert_data['generated_at']}")
            
            return 0
            
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return 1
    
    def _confirm_wipe(self, device_path: str, wipe_level: WipeLevel) -> bool:
        """Interactive confirmation for wipe operations"""
        print(f"\\n⚠️  WARNING: This will permanently destroy all data on {device_path}")
        print(f"   Wipe Level: {wipe_level.value.upper()}")
        print("   This action cannot be undone!\\n")
        
        response = input("Type 'CONFIRM' to proceed: ")
        return response.strip().upper() == "CONFIRM"
    
    def _print_device_analysis(self, analysis: dict):
        """Print device analysis in human-readable format"""
        print(f"\\nDevice Analysis for {analysis['device_path']}:")
        print("=" * 50)
        
        # Basic info
        print(f"Platform: {analysis.get('platform', 'unknown')}")
        print(f"Size: {analysis.get('size_gb', 0):.2f} GB")
        print(f"Device Type: {analysis.get('device_type', 'unknown')}")
        print(f"Encryption: {analysis.get('encryption_status', 'unknown')}")
        
        # Supported methods
        if 'nist_methods' in analysis:
            print(f"\\nSupported NIST Methods:")
            for method in analysis['nist_methods']:
                print(f"  • {method.upper()}")
        
        # Hidden areas
        if analysis.get('hidden_areas'):
            print(f"\\nHidden Areas Detected:")
            for area in analysis['hidden_areas']:
                print(f"  • {area.get('type', 'Unknown')}: {area.get('description', 'No description')}")
        
        # Estimated time
        est_time = analysis.get('estimated_time', 0)
        if est_time > 0:
            print(f"\\nEstimated Wipe Time: {est_time} seconds")

def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="SecureWipe India - NIST 800-88 Compliant Data Sanitization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                              # List all storage devices
  %(prog)s analyze --device /dev/sdb         # Analyze a specific device
  %(prog)s wipe --device /dev/sdb --level purge  # Wipe device with NIST Purge level
  %(prog)s verify --certificate cert.json   # Verify a certificate
        """
    )
    
    # Global options
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List storage devices')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a storage device')
    analyze_parser.add_argument('--device', '-d', required=True, help='Device path to analyze')
    
    # Wipe command
    wipe_parser = subparsers.add_parser('wipe', help='Wipe a storage device')
    wipe_parser.add_argument('--device', '-d', required=True, help='Device path to wipe')
    wipe_parser.add_argument('--level', '-l', choices=['clear', 'purge', 'destroy'], 
                           default='purge', help='NIST wipe level (default: purge)')
    wipe_parser.add_argument('--force', '-f', action='store_true', 
                           help='Skip confirmation prompt')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument('--certificate', '-c', required=True, 
                             help='Certificate file path')
    
    return parser

def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = SecureWipeCLI()
    return cli.run(args)

if __name__ == "__main__":
    sys.exit(main())