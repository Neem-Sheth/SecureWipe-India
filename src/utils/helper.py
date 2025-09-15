"""
SecureWipe India - Helper Utilities
Common utility functions used across the application
"""

import os
import sys
import platform
import subprocess
import hashlib
import json
import time
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "user": os.getenv("USER") or os.getenv("USERNAME", "unknown"),
        "timestamp": time.time()
    }
    
    # Add platform-specific info
    if info["platform"] == "Windows":
        info.update(get_windows_info())
    elif info["platform"] == "Linux":
        info.update(get_linux_info())
    elif info["platform"] == "Darwin":
        info.update(get_macos_info())
    
    return info

def get_windows_info() -> Dict[str, Any]:
    """Get Windows-specific information"""
    info = {}
    
    try:
        # Windows version details
        import ctypes
        info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin()
        
        # System directory
        info["system_directory"] = os.environ.get("SystemRoot", "C:\\\\Windows")
        
        # Available drives
        drives = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{letter}:\\\\"):
                drives.append(f"{letter}:")
        info["available_drives"] = drives
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

def get_linux_info() -> Dict[str, Any]:
    """Get Linux-specific information"""
    info = {}
    
    try:
        # Check if running as root
        info["is_root"] = os.getuid() == 0
        
        # Distribution information
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("NAME="):
                        info["distribution"] = line.split("=")[1].strip().strip('"')
                        break
        except FileNotFoundError:
            info["distribution"] = "Unknown"
        
        # Kernel version
        info["kernel_version"] = platform.release()
        
        # Available block devices
        block_devices = []
        if os.path.exists("/sys/block"):
            for device in os.listdir("/sys/block"):
                if not device.startswith("loop"):  # Skip loop devices
                    block_devices.append(f"/dev/{device}")
        info["block_devices"] = block_devices
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

def get_macos_info() -> Dict[str, Any]:
    """Get macOS-specific information"""
    info = {}
    
    try:
        # macOS version
        info["macos_version"] = platform.mac_ver()[0]
        
        # Check if running as root
        info["is_root"] = os.getuid() == 0
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

def format_bytes(bytes_value: int) -> str:
    """Format bytes in human-readable format"""
    
    if bytes_value == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit_index = 0
    
    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024.0
        unit_index += 1
    
    return f"{bytes_value:.2f} {units[unit_index]}"

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate hash of a file"""
    
    hash_algo = hashlib.new(algorithm)
    
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                hash_algo.update(block)
        return hash_algo.hexdigest()
    except Exception as e:
        raise IOError(f"Failed to calculate hash for {file_path}: {e}")

def is_admin() -> bool:
    """Check if running with administrator/root privileges"""
    
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except Exception:
        return False

def run_command(command: List[str], timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    """Run a system command with proper error handling"""
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check
        )
        return result
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command timed out after {timeout} seconds: {' '.join(command)}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed with exit code {e.returncode}: {' '.join(command)}\\nStderr: {e.stderr}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Command not found: {command[0]}")

def safe_json_load(file_path: str) -> Optional[Dict]:
    """Safely load JSON file with error handling"""
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {file_path}: {e}")
    except Exception as e:
        raise IOError(f"Failed to read {file_path}: {e}")

def safe_json_save(data: Dict, file_path: str, indent: int = 2) -> None:
    """Safely save data to JSON file"""
    
    try:
        # Create directory if it doesn't exist
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
    except Exception as e:
        raise IOError(f"Failed to write {file_path}: {e}")

def validate_device_path(device_path: str) -> bool:
    """Validate if a device path is valid and accessible"""
    
    if not device_path:
        return False
    
    try:
        # Check if path exists
        if not os.path.exists(device_path):
            return False
        
        # Check if it's a block device or regular file
        stat_info = os.stat(device_path)
        
        # On Unix systems, check if it's a block device
        if hasattr(stat_info, 'st_mode'):
            import stat
            if stat.S_ISBLK(stat_info.st_mode) or stat.S_ISREG(stat_info.st_mode):
                return True
        
        # On Windows, check if it's a valid drive
        if platform.system() == "Windows":
            if len(device_path) == 2 and device_path[1] == ":":
                return True
            elif device_path.startswith("\\\\\\\\.\\\\"):
                return True
        
        return False
        
    except Exception:
        return False

def get_available_space(path: str) -> int:
    """Get available disk space in bytes"""
    
    try:
        if platform.system() == "Windows":
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(path),
                ctypes.pointer(free_bytes),
                None,
                None
            )
            return free_bytes.value
        else:
            statvfs = os.statvfs(path)
            return statvfs.f_frsize * statvfs.f_bavail
    except Exception:
        return 0

def create_backup(file_path: str, backup_suffix: str = ".backup") -> str:
    """Create a backup of a file"""
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    backup_path = file_path + backup_suffix
    
    try:
        import shutil
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise IOError(f"Failed to create backup: {e}")

def cleanup_temp_files(temp_dir: str = None) -> None:
    """Clean up temporary files"""
    
    if temp_dir is None:
        temp_dir = os.path.join(os.getcwd(), "temp")
    
    if not os.path.exists(temp_dir):
        return
    
    try:
        import shutil
        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Failed to clean up temp directory {temp_dir}: {e}")

def generate_unique_id(prefix: str = "") -> str:
    """Generate a unique identifier"""
    
    import uuid
    unique_id = str(uuid.uuid4())
    
    if prefix:
        return f"{prefix}_{unique_id}"
    
    return unique_id

def verify_checksum(file_path: str, expected_checksum: str, algorithm: str = "sha256") -> bool:
    """Verify file checksum"""
    
    try:
        actual_checksum = calculate_file_hash(file_path, algorithm)
        return actual_checksum.lower() == expected_checksum.lower()
    except Exception:
        return False

class ProgressTracker:
    """Simple progress tracking utility"""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        self.current = min(self.current, self.total)
    
    def get_percentage(self) -> float:
        """Get completion percentage"""
        if self.total == 0:
            return 100.0
        return (self.current / self.total) * 100.0
    
    def get_eta(self) -> Optional[float]:
        """Get estimated time to completion"""
        if self.current == 0:
            return None
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed
        remaining = self.total - self.current
        
        if rate > 0:
            return remaining / rate
        return None
    
    def __str__(self) -> str:
        """String representation"""
        percentage = self.get_percentage()
        eta = self.get_eta()
        
        if eta:
            eta_str = f", ETA: {format_duration(eta)}"
        else:
            eta_str = ""
        
        return f"{self.description}: {percentage:.1f}% ({self.current}/{self.total}){eta_str}"