"""
SecureWipe India - Constants
Application-wide constants and configuration values
"""

# Application Information
APP_NAME = "SecureWipe India"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "NIST 800-88 Compliant Data Sanitization for India's E-Waste Crisis"
ORGANIZATION = "Government of India"
WEBSITE = "https://securewipe.india.gov.in"

# NIST Standards
NIST_STANDARD = "SP 800-88 Rev 1"
NIST_LEVELS = ["clear", "purge", "destroy"]
DEFAULT_WIPE_LEVEL = "purge"

# File Patterns and Extensions
SUPPORTED_CERT_FORMATS = [".json", ".pdf"]
LOG_FILE_EXTENSION = ".log"
CONFIG_FILE_EXTENSION = ".json"
BACKUP_FILE_SUFFIX = ".backup"

# Directory Structure
DEFAULT_CONFIG_DIR = "config"
DEFAULT_CERT_DIR = "certificates"
DEFAULT_LOG_DIR = "logs"
DEFAULT_TEMP_DIR = "temp"
DEFAULT_BACKUP_DIR = "backups"

# Wipe Operation Parameters
DEFAULT_BLOCK_SIZE = 1024 * 1024  # 1MB
MAX_VERIFICATION_SECTORS = 1000
VERIFICATION_ERROR_THRESHOLD = 0.01  # 1% tolerance
DEFAULT_TIMEOUT = 3600  # 1 hour

# Progress and UI Constants
PROGRESS_UPDATE_INTERVAL = 1.0  # seconds
MAX_LOG_LINES = 1000
UI_REFRESH_RATE = 100  # milliseconds

# Cryptographic Settings
DEFAULT_KEY_SIZE = 4096
DEFAULT_HASH_ALGORITHM = "SHA256"
DEFAULT_SIGNATURE_ALGORITHM = "RSA-PSS"
CERTIFICATE_VALIDITY_DAYS = 3650  # 10 years

# Platform-specific Constants
WINDOWS_ADMIN_REQUIRED = True
LINUX_ROOT_REQUIRED = True
ANDROID_MIN_API_LEVEL = 23

# Device Type Classifications
DEVICE_TYPES = {
    "hdd": "Hard Disk Drive",
    "ssd": "Solid State Drive", 
    "flash": "Flash Storage",
    "optical": "Optical Media",
    "unknown": "Unknown Device"
}

# Hidden Area Types
HIDDEN_AREA_TYPES = ["HPA", "DCO", "Service Area", "Reserved Blocks"]

# Supported File Systems
SUPPORTED_FILESYSTEMS = [
    "NTFS", "FAT32", "FAT16", "exFAT",
    "ext2", "ext3", "ext4", "xfs", "btrfs",
    "HFS+", "APFS"
]

# Error Codes
ERROR_CODES = {
    "SUCCESS": 0,
    "GENERAL_ERROR": 1,
    "DEVICE_NOT_FOUND": 2,
    "PERMISSION_DENIED": 3,
    "DEVICE_BUSY": 4,
    "UNSUPPORTED_OPERATION": 5,
    "VERIFICATION_FAILED": 6,
    "CERTIFICATE_ERROR": 7,
    "CONFIGURATION_ERROR": 8,
    "TIMEOUT_ERROR": 9,
    "CANCELLED_BY_USER": 10
}

# Status Messages
STATUS_MESSAGES = {
    "READY": "Ready to begin data sanitization",
    "SCANNING": "Scanning for storage devices...",
    "ANALYZING": "Analyzing device capabilities...",
    "PREPARING": "Preparing device for sanitization...",
    "WIPING": "Securely wiping data...",
    "VERIFYING": "Verifying sanitization results...",
    "GENERATING_CERT": "Generating compliance certificate...",
    "COMPLETED": "Data sanitization completed successfully",
    "FAILED": "Data sanitization failed",
    "CANCELLED": "Operation cancelled by user"
}

# Wipe Patterns
WIPE_PATTERNS = {
    "ZEROS": b'\\x00',
    "ONES": b'\\xFF',
    "RANDOM": None,  # Generated dynamically
    "DOD_5220_22_M": [b'\\x00', b'\\xFF', b'\\x92']
}

# Language Support
SUPPORTED_LANGUAGES = {
    "en": "English",
    "hi": "हिन्दी (Hindi)",
    "ta": "தமிழ் (Tamil)",
    "te": "తెలుగు (Telugu)",
    "bn": "বাংলা (Bengali)",
    "gu": "ગુજરાતી (Gujarati)",
    "kn": "ಕನ್ನಡ (Kannada)",
    "ml": "മലയാളം (Malayalam)",
    "or": "ଓଡ଼ିଆ (Odia)",
    "pa": "ਪੰਜਾਬੀ (Punjabi)",
    "as": "অসমীয়া (Assamese)",
    "mr": "मराठी (Marathi)"
}

# Default Configuration
DEFAULT_CONFIG = {
    "app_name": APP_NAME,
    "version": APP_VERSION,
    "nist_compliance": {
        "default_level": DEFAULT_WIPE_LEVEL,
        "supported_levels": NIST_LEVELS,
        "verification_passes": 3
    },
    "certificate": {
        "key_size": DEFAULT_KEY_SIZE,
        "hash_algorithm": DEFAULT_HASH_ALGORITHM,
        "validity_days": CERTIFICATE_VALIDITY_DAYS,
        "blockchain_network": "ethereum_testnet"
    },
    "ui": {
        "languages": list(SUPPORTED_LANGUAGES.keys()),
        "theme": "material_design",
        "accessibility": True,
        "progress_update_interval": PROGRESS_UPDATE_INTERVAL
    },
    "platforms": {
        "windows": {
            "admin_required": WINDOWS_ADMIN_REQUIRED,
            "supported_versions": ["7", "8", "10", "11"]
        },
        "linux": {
            "root_required": LINUX_ROOT_REQUIRED,
            "min_kernel": "4.4"
        },
        "android": {
            "min_api_level": ANDROID_MIN_API_LEVEL,
            "root_preferred": True
        }
    },
    "logging": {
        "level": "INFO",
        "max_log_files": 30,
        "max_log_size_mb": 10,
        "audit_enabled": True
    }
}

# URLs and Endpoints
VERIFICATION_BASE_URL = "https://securewipe.india.gov.in"
CERTIFICATE_VERIFY_ENDPOINT = "/api/v1/verify"
BLOCKCHAIN_ANCHOR_ENDPOINT = "/api/v1/anchor"
SUPPORT_URL = "https://support.securewipe.india.gov.in"
DOCUMENTATION_URL = "https://docs.securewipe.india.gov.in"

# Indian Government Standards
INDIAN_STANDARDS = {
    "STQC_COMPLIANCE": True,
    "DIETY_GUIDELINES": True,
    "PERSONAL_DATA_PROTECTION_ACT": True,
    "DIGITAL_INDIA_INITIATIVE": True
}

# Compliance Standards
COMPLIANCE_STANDARDS = [
    "NIST SP 800-88 Rev 1",
    "ISO/IEC 27001:2013",
    "Common Criteria EAL4+",
    "GDPR Article 17 (Right to Erasure)",
    "India Personal Data Protection Act"
]

# Hardware-specific Constants
ATA_SECURE_ERASE_TIMEOUT = 7200  # 2 hours for large drives
NVME_FORMAT_TIMEOUT = 600       # 10 minutes
SSD_OVERPROVISIONING_FACTOR = 0.1  # 10% typical overprovisioning

# Network and Connectivity
DEFAULT_CONNECT_TIMEOUT = 10  # seconds
DEFAULT_READ_TIMEOUT = 30     # seconds
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY = 2  # seconds

# File Size Limits
MAX_LOG_FILE_SIZE = 10 * 1024 * 1024      # 10MB
MAX_CERTIFICATE_SIZE = 1024 * 1024        # 1MB
MAX_CONFIG_FILE_SIZE = 100 * 1024         # 100KB

# Memory Usage Limits
MAX_MEMORY_USAGE_MB = 512  # Maximum memory usage for the application
BUFFER_SIZE_MB = 64        # Buffer size for large operations

# Quality Assurance
MINIMUM_PYTHON_VERSION = (3, 7)
RECOMMENDED_PYTHON_VERSION = (3, 9)
SUPPORTED_PLATFORMS = ["Windows", "Linux", "Darwin"]  # Darwin = macOS

# Testing and Validation
TEST_DEVICE_MIN_SIZE_MB = 100  # Minimum size for test devices
BENCHMARK_ITERATIONS = 3       # Number of benchmark runs
PERFORMANCE_THRESHOLD_MBS = 50 # Minimum expected throughput MB/s