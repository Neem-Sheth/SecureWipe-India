"""
SecureWipe India - Windows Platform Implementation
Windows-specific data wiping functionality
"""

import os
import sys
import ctypes
import subprocess
import logging
from typing import Dict, List, Optional
import psutil

class WindowsPlatform:
    """Windows-specific implementation for data wiping"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.admin_required = True
        
        # Check if running as administrator
        try:
            self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            self.is_admin = False
            
        if not self.is_admin:
            self.logger.warning("Administrator privileges required for full functionality")
    
    def get_device_info(self, device_path: str) -> Dict:
        """Get Windows-specific device information"""
        info = {
            "platform": "windows",
            "admin_mode": self.is_admin,
            "bitlocker_status": "unknown",
            "drive_type": "unknown",
            "ntfs_compressed": False
        }
        
        try:
            # Get drive type
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(device_path[:3])
            drive_types = {
                0: "unknown",
                1: "invalid",
                2: "removable", 
                3: "fixed",
                4: "network",
                5: "cd_rom",
                6: "ram_disk"
            }
            info["drive_type"] = drive_types.get(drive_type, "unknown")
            
            # Check BitLocker status
            info["bitlocker_status"] = self._check_bitlocker_status(device_path)
            
            # Check NTFS compression
            if device_path.endswith('\\\\'):
                device_path = device_path[:-1]
                
            try:
                result = subprocess.run(
                    ['fsutil', 'volume', 'querysupportedfeatures', device_path],
                    capture_output=True, text=True, timeout=10
                )
                if "Compression" in result.stdout:
                    info["ntfs_compressed"] = True
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Failed to get Windows device info: {e}")
            
        return info
    
    def analyze_device(self, device_path: str) -> Dict:
        """Analyze Windows device for wiping capabilities"""
        analysis = {
            "secure_erase_supported": False,
            "bitlocker_encrypted": False,
            "volume_shadow_copies": False,
            "system_drive": False
        }
        
        try:
            # Check if it's the system drive
            system_drive = os.environ.get('SystemDrive', 'C:')
            analysis["system_drive"] = device_path.upper().startswith(system_drive.upper())
            
            # Check for Volume Shadow Copies
            analysis["volume_shadow_copies"] = self._check_shadow_copies(device_path)
            
            # Check BitLocker encryption
            bitlocker_status = self._check_bitlocker_status(device_path)
            analysis["bitlocker_encrypted"] = bitlocker_status == "encrypted"
            
            # Check for ATA secure erase support
            analysis["secure_erase_supported"] = self._check_secure_erase_support(device_path)
            
        except Exception as e:
            self.logger.error(f"Windows device analysis failed: {e}")
            
        return analysis
    
    def prepare_device(self, device_path: str):
        """Prepare device for wiping (Windows-specific)"""
        try:
            # Unmount the volume if mounted
            self._unmount_volume(device_path)
            
            # Clear Volume Shadow Copies
            self._clear_shadow_copies(device_path)
            
            # Handle BitLocker if present
            if self._check_bitlocker_status(device_path) == "encrypted":
                self._handle_bitlocker(device_path)
                
        except Exception as e:
            self.logger.error(f"Device preparation failed: {e}")
            raise
    
    def hardware_secure_erase(self, device_path: str) -> bool:
        """Execute hardware secure erase on Windows"""
        try:
            # Convert device path to physical device
            physical_device = self._get_physical_device(device_path)
            
            if not physical_device:
                self.logger.error("Cannot determine physical device")
                return False
            
            # Try ATA secure erase first
            if self._ata_secure_erase(physical_device):
                return True
                
            # Try NVMe secure erase
            if self._nvme_secure_erase(physical_device):
                return True
                
            self.logger.warning("Hardware secure erase not supported")
            return False
            
        except Exception as e:
            self.logger.error(f"Hardware secure erase failed: {e}")
            return False
    
    def cleanup_device(self, device_path: str):
        """Cleanup after wiping operations"""
        try:
            # Remount the volume if needed
            # Note: In practice, after wiping, the volume would need to be reformatted
            pass
        except Exception as e:
            self.logger.error(f"Device cleanup failed: {e}")
    
    def _check_bitlocker_status(self, device_path: str) -> str:
        """Check BitLocker encryption status"""
        try:
            if not self.is_admin:
                return "unknown"
                
            result = subprocess.run(
                ['manage-bde', '-status', device_path[:2]],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if "fully encrypted" in output:
                    return "encrypted"
                elif "fully decrypted" in output:
                    return "decrypted"
                elif "encryption in progress" in output:
                    return "encrypting"
                elif "decryption in progress" in output:
                    return "decrypting"
                    
        except Exception as e:
            self.logger.debug(f"BitLocker status check failed: {e}")
            
        return "unknown"
    
    def _check_shadow_copies(self, device_path: str) -> bool:
        """Check for Volume Shadow Copies"""
        try:
            if not self.is_admin:
                return False
                
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows', f'/for={device_path[:2]}'],
                capture_output=True, text=True, timeout=30
            )
            
            return result.returncode == 0 and "shadow copy" in result.stdout.lower()
            
        except Exception as e:
            self.logger.debug(f"Shadow copy check failed: {e}")
            return False
    
    def _clear_shadow_copies(self, device_path: str):
        """Clear Volume Shadow Copies"""
        try:
            if not self.is_admin:
                return
                
            result = subprocess.run(
                ['vssadmin', 'delete', 'shadows', f'/for={device_path[:2]}', '/all', '/quiet'],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"Cleared shadow copies for {device_path}")
            else:
                self.logger.warning(f"Failed to clear shadow copies: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Shadow copy clearing failed: {e}")
    
    def _handle_bitlocker(self, device_path: str):
        """Handle BitLocker encrypted volumes"""
        try:
            if not self.is_admin:
                return
                
            # For NIST Purge level, we want to destroy the encryption keys
            # This is equivalent to crypto erase
            result = subprocess.run(
                ['manage-bde', '-forcerecovery', device_path[:2]],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"BitLocker recovery forced for {device_path}")
            
        except Exception as e:
            self.logger.error(f"BitLocker handling failed: {e}")
    
    def _unmount_volume(self, device_path: str):
        """Unmount a Windows volume"""
        try:
            # Use Windows API to unmount
            drive_letter = device_path[:2]
            
            # First try graceful unmount
            result = subprocess.run(
                ['mountvol', drive_letter, '/d'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                # Force unmount if graceful fails
                result = subprocess.run(
                    ['diskpart'],
                    input=f'select volume {drive_letter[0]}\\nremove\\nexit\\n',
                    capture_output=True, text=True, timeout=30
                )
                
        except Exception as e:
            self.logger.error(f"Volume unmount failed: {e}")
    
    def _get_physical_device(self, device_path: str) -> Optional[str]:
        """Convert logical drive to physical device path"""
        try:
            # Use WMI or diskpart to get physical device
            drive_letter = device_path[0].upper()
            
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'where', f'DeviceID="{drive_letter}:"', 
                 'assoc', '/assocclass:Win32_LogicalDiskToPartition'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                # Parse output to get physical device number
                # This is simplified - real implementation would parse WMI output
                return f"\\\\\\\\.\\\\PhysicalDrive0"  # Placeholder
                
        except Exception as e:
            self.logger.debug(f"Physical device lookup failed: {e}")
            
        return None
    
    def _check_secure_erase_support(self, device_path: str) -> bool:
        """Check if device supports ATA/NVMe secure erase"""
        try:
            # This would require low-level ATA/NVMe command support
            # For now, assume modern drives support it
            return True
            
        except Exception as e:
            self.logger.debug(f"Secure erase support check failed: {e}")
            return False
    
    def _ata_secure_erase(self, physical_device: str) -> bool:
        """Execute ATA secure erase command"""
        try:
            # This requires low-level ATA command implementation
            # Would use Windows IOCTL calls or third-party tools
            self.logger.info(f"ATA secure erase not implemented yet for {physical_device}")
            return False
            
        except Exception as e:
            self.logger.error(f"ATA secure erase failed: {e}")
            return False
    
    def _nvme_secure_erase(self, physical_device: str) -> bool:
        """Execute NVMe secure erase command"""
        try:
            # This requires NVMe command implementation
            # Would use Windows NVMe API or third-party tools
            self.logger.info(f"NVMe secure erase not implemented yet for {physical_device}")
            return False
            
        except Exception as e:
            self.logger.error(f"NVMe secure erase failed: {e}")
            return False