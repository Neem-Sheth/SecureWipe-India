# SecureWipe India - Optimal Fast Secure Erase
# Hardware-level secure erase implementation for maximum speed and security
# File: src/core/optimal_erase.py

import os
import sys
import subprocess
import logging
import time
import re
from typing import Dict, List, Optional, Tuple
from enum import Enum
import platform

class SecureEraseMethod(Enum):
    ATA_SECURE_ERASE = "ata_secure_erase"
    ATA_ENHANCED_SECURE_ERASE = "ata_enhanced_secure_erase"
    NVME_FORMAT = "nvme_format"
    NVME_SANITIZE = "nvme_sanitize"
    SCSI_SANITIZE = "scsi_sanitize"
    CRYPTO_ERASE = "crypto_erase"
    TRIM_FULL_DEVICE = "trim_full_device"
    FALLBACK_OVERWRITE = "fallback_overwrite"

class OptimalSecureErase:
    """Implements optimal hardware-level secure erase for maximum speed and security"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system().lower()
        
        # Check available tools
        self._check_tools()
    
    def _check_tools(self):
        """Check availability of secure erase tools"""
        self.available_tools = {}
        
        if self.platform == "linux":
            tools = ["hdparm", "nvme", "sg_sanitize", "blkdiscard", "smartctl"]
        elif self.platform == "windows":
            tools = ["diskpart", "cipher", "sdelete"]
        else:
            tools = []
        
        for tool in tools:
            try:
                result = subprocess.run([tool, "--version"], capture_output=True, timeout=5)
                self.available_tools[tool] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self.available_tools[tool] = False
    
    def detect_optimal_method(self, device_path: str, device_info: Dict) -> Tuple[SecureEraseMethod, Dict]:
        """Detect the optimal secure erase method for a device"""
        
        method_info = {
            "method": SecureEraseMethod.FALLBACK_OVERWRITE,
            "estimated_time": 3600,  # Default: 1 hour fallback
            "security_level": "high",
            "nist_compliance": "purge"
        }
        
        try:
            # Detect device type and capabilities
            device_type = device_info.get("device_type", "unknown").lower()
            is_ssd = not device_info.get("rotational", True)
            is_encrypted = device_info.get("encrypted", False)
            
            if self.platform == "linux":
                return self._detect_linux_optimal_method(device_path, device_type, is_ssd, is_encrypted)
            elif self.platform == "windows":
                return self._detect_windows_optimal_method(device_path, device_type, is_ssd, is_encrypted)
            else:
                return SecureEraseMethod.FALLBACK_OVERWRITE, method_info
                
        except Exception as e:
            self.logger.error(f"Method detection failed: {e}")
            return SecureEraseMethod.FALLBACK_OVERWRITE, method_info
    
    def _detect_linux_optimal_method(self, device_path: str, device_type: str, is_ssd: bool, is_encrypted: bool) -> Tuple[SecureEraseMethod, Dict]:
        """Detect optimal method for Linux"""
        
        # Encrypted devices (fastest)
        if is_encrypted:
            return SecureEraseMethod.CRYPTO_ERASE, {
                "method": SecureEraseMethod.CRYPTO_ERASE,
                "estimated_time": 5,  # 5 seconds
                "security_level": "maximum",
                "nist_compliance": "purge"
            }
        
        # NVMe devices
        if "nvme" in device_path:
            if self._check_nvme_sanitize_support(device_path):
                return SecureEraseMethod.NVME_SANITIZE, {
                    "method": SecureEraseMethod.NVME_SANITIZE,
                    "estimated_time": 60,  # 1 minute
                    "security_level": "maximum",
                    "nist_compliance": "purge"
                }
            elif self._check_nvme_format_support(device_path):
                return SecureEraseMethod.NVME_FORMAT, {
                    "method": SecureEraseMethod.NVME_FORMAT,
                    "estimated_time": 120,  # 2 minutes
                    "security_level": "high",
                    "nist_compliance": "purge"
                }
        
        # SATA/ATA devices
        elif device_type in ["sata", "ata", "disk"] or device_path.startswith("/dev/sd"):
            if self._check_ata_secure_erase_support(device_path):
                enhanced = self._check_ata_enhanced_secure_erase_support(device_path)
                if enhanced:
                    return SecureEraseMethod.ATA_ENHANCED_SECURE_ERASE, {
                        "method": SecureEraseMethod.ATA_ENHANCED_SECURE_ERASE,
                        "estimated_time": 300,  # 5 minutes
                        "security_level": "maximum", 
                        "nist_compliance": "purge"
                    }
                else:
                    return SecureEraseMethod.ATA_SECURE_ERASE, {
                        "method": SecureEraseMethod.ATA_SECURE_ERASE,
                        "estimated_time": 600,  # 10 minutes
                        "security_level": "high",
                        "nist_compliance": "purge"
                    }
        
        # SSD with TRIM support
        elif is_ssd and self._check_trim_support(device_path):
            return SecureEraseMethod.TRIM_FULL_DEVICE, {
                "method": SecureEraseMethod.TRIM_FULL_DEVICE,
                "estimated_time": 180,  # 3 minutes
                "security_level": "high",
                "nist_compliance": "clear"
            }
        
        # Fallback to overwrite
        return SecureEraseMethod.FALLBACK_OVERWRITE, {
            "method": SecureEraseMethod.FALLBACK_OVERWRITE,
            "estimated_time": 3600,  # 1 hour
            "security_level": "medium",
            "nist_compliance": "clear"
        }
    
    def _detect_windows_optimal_method(self, device_path: str, device_type: str, is_ssd: bool, is_encrypted: bool) -> Tuple[SecureEraseMethod, Dict]:
        """Detect optimal method for Windows"""
        
        # Check for BitLocker encryption first
        if is_encrypted or self._check_bitlocker_status(device_path):
            return SecureEraseMethod.CRYPTO_ERASE, {
                "method": SecureEraseMethod.CRYPTO_ERASE,
                "estimated_time": 30,  # 30 seconds
                "security_level": "maximum",
                "nist_compliance": "purge"
            }
        
        # Try to detect hardware secure erase capability
        if self._check_windows_secure_erase_support(device_path):
            return SecureEraseMethod.ATA_SECURE_ERASE, {
                "method": SecureEraseMethod.ATA_SECURE_ERASE,
                "estimated_time": 600,  # 10 minutes
                "security_level": "high", 
                "nist_compliance": "purge"
            }
        
        # Fallback to cipher.exe for fast overwrite
        return SecureEraseMethod.FALLBACK_OVERWRITE, {
            "method": SecureEraseMethod.FALLBACK_OVERWRITE,
            "estimated_time": 1800,  # 30 minutes
            "security_level": "medium",
            "nist_compliance": "clear"
        }
    
    def execute_optimal_erase(self, device_path: str, method: SecureEraseMethod, 
                            progress_callback=None) -> Dict:
        """Execute the optimal secure erase method"""
        
        result = {
            "success": False,
            "method_used": method,
            "duration": 0,
            "error": None,
            "verification": None
        }
        
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing {method.value} on {device_path}")
            
            if method == SecureEraseMethod.ATA_SECURE_ERASE:
                success = self._execute_ata_secure_erase(device_path, False, progress_callback)
            elif method == SecureEraseMethod.ATA_ENHANCED_SECURE_ERASE:
                success = self._execute_ata_secure_erase(device_path, True, progress_callback)
            elif method == SecureEraseMethod.NVME_FORMAT:
                success = self._execute_nvme_format(device_path, progress_callback)
            elif method == SecureEraseMethod.NVME_SANITIZE:
                success = self._execute_nvme_sanitize(device_path, progress_callback)
            elif method == SecureEraseMethod.SCSI_SANITIZE:
                success = self._execute_scsi_sanitize(device_path, progress_callback)
            elif method == SecureEraseMethod.CRYPTO_ERASE:
                success = self._execute_crypto_erase(device_path, progress_callback)
            elif method == SecureEraseMethod.TRIM_FULL_DEVICE:
                success = self._execute_trim_full_device(device_path, progress_callback)
            else:
                success = self._execute_fallback_overwrite(device_path, progress_callback)
            
            result["success"] = success
            result["duration"] = time.time() - start_time
            
            if success:
                self.logger.info(f"Optimal erase completed in {result['duration']:.1f} seconds")
            else:
                self.logger.error("Optimal erase failed")
                
        except Exception as e:
            result["error"] = str(e)
            result["duration"] = time.time() - start_time
            self.logger.error(f"Optimal erase failed: {e}")
        
        return result
    
    def _execute_ata_secure_erase(self, device_path: str, enhanced: bool, progress_callback) -> bool:
        """Execute ATA secure erase command"""
        try:
            if progress_callback:
                progress_callback(10, "Preparing ATA secure erase...")
            
            # Set security password (required for erase)
            cmd_set = ["hdparm", "--user-master", "u", "--security-set-pass", "SecureWipe", device_path]
            result = subprocess.run(cmd_set, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.logger.error(f"Failed to set security password: {result.stderr}")
                return False
            
            if progress_callback:
                progress_callback(20, "Executing secure erase...")
            
            # Execute secure erase
            erase_type = "enhanced-security-erase" if enhanced else "security-erase"
            cmd_erase = ["hdparm", "--user-master", "u", f"--{erase_type}", "SecureWipe", device_path]
            
            # This can take a long time
            result = subprocess.run(cmd_erase, capture_output=True, text=True, timeout=7200)
            
            if progress_callback:
                progress_callback(100, "ATA secure erase completed")
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            self.logger.error("ATA secure erase timed out")
            return False
        except Exception as e:
            self.logger.error(f"ATA secure erase failed: {e}")
            return False
    
    def _execute_nvme_format(self, device_path: str, progress_callback) -> bool:
        """Execute NVMe format with secure erase"""
        try:
            if progress_callback:
                progress_callback(20, "Starting NVMe format...")
            
            # NVMe format with secure erase setting
            cmd = ["nvme", "format", device_path, "--ses=1", "--force"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if progress_callback:
                progress_callback(100, "NVMe format completed")
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"NVMe format failed: {e}")
            return False
    
    def _execute_nvme_sanitize(self, device_path: str, progress_callback) -> bool:
        """Execute NVMe sanitize command"""
        try:
            if progress_callback:
                progress_callback(20, "Starting NVMe sanitize...")
            
            # NVMe sanitize command
            cmd = ["nvme", "sanitize", device_path, "--sanact=2", "--force"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if progress_callback:
                progress_callback(100, "NVMe sanitize completed")
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"NVMe sanitize failed: {e}")
            return False
    
    def _execute_trim_full_device(self, device_path: str, progress_callback) -> bool:
        """Execute TRIM/discard on full device"""
        try:
            if progress_callback:
                progress_callback(20, "Starting full device TRIM...")
            
            # Use blkdiscard to TRIM entire device
            cmd = ["blkdiscard", "-v", device_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if progress_callback:
                progress_callback(100, "TRIM operation completed")
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"TRIM operation failed: {e}")
            return False
    
    def _execute_crypto_erase(self, device_path: str, progress_callback) -> bool:
        """Execute cryptographic erase (destroy encryption keys)"""
        try:
            if progress_callback:
                progress_callback(20, "Destroying encryption keys...")
            
            if self.platform == "linux":
                # For LUKS devices
                if self._is_luks_device(device_path):
                    cmd = ["cryptsetup", "erase", device_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    success = result.returncode == 0
                else:
                    success = False
                    
            elif self.platform == "windows":
                # For BitLocker devices
                drive_letter = device_path[:2] if len(device_path) >= 2 else "C:"
                cmd = ["manage-bde", "-forcerecovery", drive_letter]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                success = result.returncode == 0
            else:
                success = False
            
            if progress_callback:
                progress_callback(100, "Cryptographic erase completed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Crypto erase failed: {e}")
            return False
    
    def _execute_fallback_overwrite(self, device_path: str, progress_callback) -> bool:
        """Execute single-pass overwrite as fallback"""
        try:
            if progress_callback:
                progress_callback(5, "Starting fast single-pass overwrite...")
            
            # Use platform-specific fast overwrite
            if self.platform == "linux":
                # Use dd with fast random overwrite
                cmd = ["dd", f"if=/dev/urandom", f"of={device_path}", "bs=1M", "status=progress"]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Monitor progress
                while process.poll() is None:
                    if progress_callback:
                        progress_callback(50, "Overwriting device...")
                    time.sleep(10)
                
                success = process.returncode == 0
                
            elif self.platform == "windows":
                # Use cipher.exe for fast overwrite
                cmd = ["cipher", "/w:" + device_path[:3]]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                success = result.returncode == 0
            else:
                success = False
            
            if progress_callback:
                progress_callback(100, "Fallback overwrite completed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Fallback overwrite failed: {e}")
            return False
    
    # Helper methods for capability detection
    def _check_nvme_sanitize_support(self, device_path: str) -> bool:
        """Check if NVMe device supports sanitize"""
        try:
            result = subprocess.run(["nvme", "id-ctrl", device_path], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return "sanicap" in result.stdout.lower()
        except:
            pass
        return False
    
    def _check_nvme_format_support(self, device_path: str) -> bool:
        """Check if NVMe device supports format"""
        try:
            result = subprocess.run(["nvme", "id-ctrl", device_path], capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except:
            pass
        return False
    
    def _check_ata_secure_erase_support(self, device_path: str) -> bool:
        """Check if device supports ATA secure erase"""
        try:
            result = subprocess.run(["hdparm", "-I", device_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout.lower()
                return "supported:" in output and "erase" in output
        except:
            pass
        return False
    
    def _check_ata_enhanced_secure_erase_support(self, device_path: str) -> bool:
        """Check if device supports enhanced secure erase"""
        try:
            result = subprocess.run(["hdparm", "-I", device_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout.lower()
                return "supported: enhanced erase" in output
        except:
            pass
        return False
    
    def _check_trim_support(self, device_path: str) -> bool:
        """Check if device supports TRIM/discard"""
        try:
            device_name = os.path.basename(device_path)
            discard_file = f"/sys/block/{device_name}/queue/discard_granularity"
            
            if os.path.exists(discard_file):
                with open(discard_file, 'r') as f:
                    granularity = int(f.read().strip())
                    return granularity > 0
        except:
            pass
        return False
    
    def _is_luks_device(self, device_path: str) -> bool:
        """Check if device is LUKS encrypted"""
        try:
            result = subprocess.run(["cryptsetup", "isLuks", device_path], capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            pass
        return False
    
    def _check_bitlocker_status(self, device_path: str) -> bool:
        """Check BitLocker status on Windows"""
        try:
            drive_letter = device_path[:2] if len(device_path) >= 2 else "C:"
            result = subprocess.run(["manage-bde", "-status", drive_letter], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return "encrypted" in result.stdout.lower()
        except:
            pass
        return False
    
    def _check_windows_secure_erase_support(self, device_path: str) -> bool:
        """Check Windows secure erase support (simplified)"""
        # This would require more complex WMI queries or vendor tools
        return False
    
    def _check_scsi_sanitize_support(self, device_path: str) -> bool:
        """Check SCSI sanitize support"""
        try:
            result = subprocess.run(["sg_sanitize", "--test", device_path], capture_output=True, timeout=15)
            return result.returncode == 0
        except:
            pass
        return False