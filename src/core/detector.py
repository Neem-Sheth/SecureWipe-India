"""
SecureWipe India - Storage Detector
Detects and analyzes storage devices across platforms
"""

import os
import re
import subprocess
import psutil
from typing import List, Dict
import logging

class StorageDetector:
    """Detects and analyzes storage devices"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def scan_devices(self) -> List[Dict]:
        """Scan for all storage devices on the system"""
        devices = []
        
        try:
            # Get disk partitions
            partitions = psutil.disk_partitions(all=True)
            
            # Get unique physical devices
            seen_devices = set()
            
            for partition in partitions:
                device_info = self._get_device_info(partition.device)
                
                # Skip if already seen
                device_key = device_info.get('physical_device', partition.device)
                if device_key in seen_devices:
                    continue
                    
                seen_devices.add(device_key)
                devices.append(device_info)
                
        except Exception as e:
            self.logger.error(f"Failed to scan devices: {e}")
        
        return devices
    
    def analyze_device(self, device_path: str) -> Dict:
        """Analyze a specific device"""
        analysis = {
            "path": device_path,
            "size_bytes": 0,
            "size_gb": 0,
            "device_type": "unknown",
            "file_system": "unknown",
            "mount_point": None,
            "removable": False
        }
        
        try:
            # Get basic info using psutil
            if os.path.exists(device_path):
                stat_info = os.stat(device_path)
                
                # Try to get size
                try:
                    with open(device_path, 'rb') as f:
                        f.seek(0, 2)  # Seek to end
                        analysis["size_bytes"] = f.tell()
                        analysis["size_gb"] = analysis["size_bytes"] / (1024**3)
                except (PermissionError, OSError):
                    self.logger.warning(f"Cannot determine size of {device_path}")
                
                # Check if it's a block device
                if os.path.isfile(device_path):
                    analysis["device_type"] = "file"
                elif os.path.isdir(device_path):
                    analysis["device_type"] = "directory"
                else:
                    analysis["device_type"] = "block_device"
                
        except Exception as e:
            self.logger.error(f"Failed to analyze device {device_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def detect_hidden_areas(self, device_path: str) -> List[Dict]:
        """Detect Hidden Protected Areas (HPA) and Device Configuration Overlay (DCO)"""
        hidden_areas = []
        
        try:
            # Try to detect HPA using hdparm
            hpa_info = self._detect_hpa(device_path)
            if hpa_info:
                hidden_areas.append(hpa_info)
            
            # Try to detect DCO
            dco_info = self._detect_dco(device_path)
            if dco_info:
                hidden_areas.append(dco_info)
                
        except Exception as e:
            self.logger.error(f"Failed to detect hidden areas on {device_path}: {e}")
        
        return hidden_areas
    
    def _get_device_info(self, device_path: str) -> Dict:
        """Get basic device information"""
        info = {
            "path": device_path,
            "name": os.path.basename(device_path),
            "size_bytes": 0,
            "size_gb": 0,
            "device_type": "unknown",
            "file_system": "unknown",
            "mount_point": None,
            "removable": False
        }
        
        try:
            # Find matching disk partition
            for partition in psutil.disk_partitions(all=True):
                if partition.device == device_path:
                    info["file_system"] = partition.fstype
                    info["mount_point"] = partition.mountpoint
                    break
            
            # Try to get disk usage if mounted
            if info["mount_point"]:
                try:
                    usage = psutil.disk_usage(info["mount_point"])
                    info["size_bytes"] = usage.total
                    info["size_gb"] = usage.total / (1024**3)
                except Exception:
                    pass
            
        except Exception as e:
            self.logger.error(f"Failed to get device info for {device_path}: {e}")
        
        return info
    
    def _detect_hpa(self, device_path: str) -> Dict:
        """Detect Host Protected Area using hdparm"""
        try:
            result = subprocess.run(
                ['hdparm', '-N', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "HPA" in result.stdout:
                return {
                    "type": "HPA",
                    "description": "Host Protected Area detected",
                    "details": result.stdout.strip()
                }
                
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"HPA detection failed: {e}")
        
        return None
    
    def _detect_dco(self, device_path: str) -> Dict:
        """Detect Device Configuration Overlay using hdparm"""
        try:
            result = subprocess.run(
                ['hdparm', '--dco-identify', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "DCO" in result.stdout:
                return {
                    "type": "DCO",
                    "description": "Device Configuration Overlay detected",
                    "details": result.stdout.strip()
                }
                
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"DCO detection failed: {e}")
        
        return None
    
    def get_device_serial(self, device_path: str) -> str:
        """Get device serial number"""
        try:
            result = subprocess.run(
                ['hdparm', '-I', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse serial number from output
                for line in result.stdout.split('\\n'):
                    if 'Serial Number' in line:
                        return line.split(':')[-1].strip()
                        
        except Exception as e:
            self.logger.debug(f"Failed to get serial for {device_path}: {e}")
        
        return "Unknown"
    
    def get_device_model(self, device_path: str) -> str:
        """Get device model"""
        try:
            result = subprocess.run(
                ['hdparm', '-I', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse model from output
                for line in result.stdout.split('\\n'):
                    if 'Model Number' in line:
                        return line.split(':')[-1].strip()
                        
        except Exception as e:
            self.logger.debug(f"Failed to get model for {device_path}: {e}")
        
        return "Unknown"