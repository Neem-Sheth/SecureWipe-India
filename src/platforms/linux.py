"""
SecureWipe India - Linux Platform Implementation
Linux-specific data wiping functionality for Ubuntu and other distributions

# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev
sudo apt-get install -y hdparm smartmontools util-linux parted
sudo apt-get install -y cryptsetup nvme-cli sg3-utils secure-delete

# Install SecureWipe India
cd SecureWipe-India
pip3 install -r requirements.txt
sudo python3 setup.py install

# Add user to disk group for device access
sudo usermod -a -G disk $USER

--------------------------------------------------

# List all storage devices (safe)
securewipe list

# Analyze a specific device (read-only)
securewipe analyze --device /dev/sdb

# Wipe external USB drive (DANGEROUS!)
securewipe wipe --device /dev/sdb --level purge --force

# Create bootable ISO
securewipe-bootable --iso --output SecureWipe-Live.iso

--------------------------------------------------

# Start graphical interface
securewipe-gui

# Or run directly from source
python3 -m src.ui.main_gui

"""

import os
import sys
import subprocess
import logging
import re
import time
from typing import Dict, List, Optional, Tuple
import psutil
from pathlib import Path

class LinuxPlatform:
    """Linux-specific implementation for data wiping"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.root_required = True
        
        # Check if running as root
        self.is_root = os.getuid() == 0
        
        if not self.is_root:
            self.logger.warning("Root privileges required for full functionality")
        
        # Detect Linux distribution
        self.distro_info = self._detect_distribution()
        self.logger.info(f"Detected Linux distribution: {self.distro_info['name']} {self.distro_info['version']}")
        
        # Check available tools
        self._check_available_tools()
    
    def _detect_distribution(self) -> Dict[str, str]:
        """Detect Linux distribution and version"""
        distro_info = {
            "name": "Unknown",
            "version": "Unknown", 
            "id": "unknown",
            "codename": "unknown"
        }
        
        try:
            # Try /etc/os-release first (modern standard)
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("NAME="):
                            distro_info["name"] = line.split("=")[1].strip().strip('"')
                        elif line.startswith("VERSION="):
                            distro_info["version"] = line.split("=")[1].strip().strip('"')
                        elif line.startswith("ID="):
                            distro_info["id"] = line.split("=")[1].strip().strip('"')
                        elif line.startswith("VERSION_CODENAME="):
                            distro_info["codename"] = line.split("=")[1].strip().strip('"')
                            
        except Exception as e:
            self.logger.warning(f"Could not detect distribution: {e}")
        
        return distro_info
    
    def get_device_info(self, device_path: str) -> Dict:
        """Get Linux-specific device information"""
        info = {
            "platform": "linux",
            "root_mode": self.is_root,
            "filesystem": "unknown",
            "mount_point": None,
            "device_type": "unknown",
            "rotational": True,
            "removable": False,
            "encrypted": False,
            "scheduler": "unknown"
        }
        
        try:
            # Get filesystem information
            info.update(self._get_filesystem_info(device_path))
            
            # Get block device information
            info.update(self._get_block_device_info(device_path))
            
            # Check if device is mounted
            info["mount_point"] = self._get_mount_point(device_path)
            
            # Check encryption status
            info["encrypted"] = self._check_encryption_status(device_path)
            
        except Exception as e:
            self.logger.error(f"Failed to get Linux device info: {e}")
            
        return info
    
    def hardware_secure_erase(self, device_path: str) -> bool:
        """Execute hardware secure erase on Linux"""
        try:
            if not self.is_root:
                self.logger.error("Root privileges required for hardware secure erase")
                return False
            
            # Try different methods based on device type
            device_info = self.analyze_device(device_path)
            
            # NVMe secure erase
            if "nvme" in device_path and device_info.get("nvme_format_supported"):
                return self._nvme_secure_erase(device_path)
            
            # ATA secure erase
            elif device_info.get("secure_erase_supported"):
                return self._ata_secure_erase(device_path)
            
            # TRIM/discard for SSDs
            elif device_info.get("trim_supported"):
                return self._trim_erase(device_path)
            
            self.logger.warning("No hardware secure erase method available")
            return False
            
        except Exception as e:
            self.logger.error(f"Hardware secure erase failed: {e}")
            return False
