"""
SecureWipe India - Main GUI Application
Cross-platform graphical user interface using PyQt5
"""

import sys
import os
import json
from typing import Optional, Dict, List
from datetime import datetime
import logging
import time

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QProgressBar, QTextEdit, QComboBox,
        QListWidget, QListWidgetItem, QMessageBox, QDialog,
        QDialogButtonBox, QFormLayout, QLineEdit, QCheckBox,
        QTabWidget, QGroupBox, QTableWidget, QTableWidgetItem,
        QSplitter, QFrame
    )
    from PyQt5.QtWidgets import QInputDialog
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    print("PyQt5 not available. Install with: pip install PyQt5")

if PYQT_AVAILABLE:
    # Import core modules. Prefer 'src.' package imports when running via
    # the project entrypoint which adds 'src' to sys.path; fall back to
    # local imports for direct execution.
    try:
        from src.core.engine import SecureWipeEngine, WipeLevel, WipeResult
    except Exception:
        from src.core.engine import SecureWipeEngine, WipeLevel, WipeResult

# SecureWipe India - GUI Integration for Optimal Erase
# Add these components to your existing main_gui.py file
# File: src/ui/main_gui_optimal_additions.py

# ADD THESE IMPORTS at the top of main_gui.py:
from src.core.optimal_erase import OptimalSecureErase, SecureEraseMethod

# ADD THIS CLASS to main_gui.py:
class OptimalEraseDialog(QDialog):
    """Dialog for optimal erase options"""
    
    def __init__(self, device_info: Dict, parent=None):
        super().__init__(parent)
        self.device_info = device_info
        self.optimal_erase = OptimalSecureErase()
        self.selected_method = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Optimal Secure Erase Options")
        self.setModal(True)
        self.resize(600, 500)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("🚀 Optimal Fast Secure Erase")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setStyleSheet("color: #1976D2; margin: 10px;")
        layout.addWidget(header_label)
        
        # Device info
        device_group = QGroupBox("Device Information")
        device_layout = QVBoxLayout()
        
        device_path = self.device_info.get('path', 'unknown')
        device_size = self.device_info.get('size_gb', 0)
        device_type = self.device_info.get('device_type', 'unknown')
        
        device_layout.addWidget(QLabel(f"Device: {device_path}"))
        device_layout.addWidget(QLabel(f"Size: {device_size:.2f} GB"))
        device_layout.addWidget(QLabel(f"Type: {device_type}"))
        
        device_group.setLayout(device_layout)
        layout.addWidget(device_group)
        
        # Detect optimal method
        method, method_info = self.optimal_erase.detect_optimal_method(
            device_path, self.device_info
        )
        
        # Method selection
        method_group = QGroupBox("Recommended Optimal Method")
        method_layout = QVBoxLayout()
        
        # Method info display
        method_name = method.value.replace('_', ' ').title()
        est_time = method_info.get('estimated_time', 0)
        security_level = method_info.get('security_level', 'unknown')
        
        time_str = self._format_time(est_time)
        
        method_layout.addWidget(QLabel(f"🎯 Method: {method_name}"))
        method_layout.addWidget(QLabel(f"⏱️ Estimated Time: {time_str}"))
        method_layout.addWidget(QLabel(f"🛡️ Security Level: {security_level.title()}"))
        method_layout.addWidget(QLabel(f"📋 NIST Compliance: {method_info.get('nist_compliance', 'unknown').upper()}"))
        
        # Speed comparison
        comparison_text = self._get_speed_comparison(est_time)
        comparison_label = QLabel(comparison_text)
        comparison_label.setStyleSheet("background-color: #e8f5e8; padding: 10px; border-radius: 5px; margin: 5px;")
        comparison_label.setWordWrap(True)
        method_layout.addWidget(comparison_label)
        
        method_group.setLayout(method_layout)
        layout.addWidget(method_group)
        
        self.selected_method = method
        
        # Warning
        warning_group = QGroupBox("⚠️ Important Warning")
        warning_layout = QVBoxLayout()
        
        warning_text = """This optimal erase method will:
• PERMANENTLY destroy ALL data on the selected device
• Use hardware-level commands for maximum speed and security
• Make data recovery IMPOSSIBLE even with professional tools
• Complete much faster than traditional overwrite methods

ENSURE YOU HAVE BACKUPS of any important data!"""
        
        warning_label = QLabel(warning_text)
        warning_label.setStyleSheet("background-color: #fff3cd; padding: 10px; border-radius: 5px; color: #856404;")
        warning_label.setWordWrap(True)
        warning_layout.addWidget(warning_label)
        
        warning_group.setLayout(warning_layout)
        layout.addWidget(warning_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.proceed_btn = QPushButton("🚀 Proceed with Optimal Erase")
        self.proceed_btn.setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; padding: 10px; }")
        
        self.cancel_btn = QPushButton("❌ Cancel")
        self.cancel_btn.setStyleSheet("QPushButton { background-color: #dc3545; color: white; padding: 10px; }")
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.proceed_btn)
        
        layout.addLayout(button_layout)
        
        # Connect buttons
        self.proceed_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        
        self.setLayout(layout)
    
    def _format_time(self, seconds: int) -> str:
        """Format time duration"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            return f"{seconds // 60} minutes"
        else:
            return f"{seconds // 3600} hours {(seconds % 3600) // 60} minutes"
    
    def _get_speed_comparison(self, est_time: int) -> str:
        """Get speed comparison text"""
        traditional_time = 3600  # Assume 1 hour for traditional method
        
        if est_time < traditional_time:
            speedup = traditional_time / est_time
            return f"🚀 This method is approximately {speedup:.1f}x FASTER than traditional overwrite methods!"
        else:
            return "ℹ️ This is the best available method for your device type."

# ADD THIS CLASS to main_gui.py:
class OptimalWipeWorkerThread(QThread):
    """Worker thread for optimal wipe operations"""
    
    progress_updated = pyqtSignal(int, str)  # Progress percentage and message
    status_updated = pyqtSignal(str)         # Status message
    wipe_completed = pyqtSignal(dict)        # Result dictionary
    
    def __init__(self, device_path: str, method: SecureEraseMethod):
        super().__init__()
        self.device_path = device_path
        self.method = method
        self.is_cancelled = False
    
    def run(self):
        """Execute the optimal wipe operation"""
        try:
            optimal_erase = OptimalSecureErase()
            
            def progress_callback(percentage, message=""):
                if not self.is_cancelled:
                    self.progress_updated.emit(int(percentage), message)
            
            self.status_updated.emit("Starting optimal secure erase...")
            result = optimal_erase.execute_optimal_erase(
                self.device_path, 
                self.method,
                progress_callback
            )
            
            self.wipe_completed.emit(result)
            
        except Exception as e:
            result = {
                "success": False,
                "method_used": self.method,
                "duration": 0,
                "error": str(e)
            }
            self.wipe_completed.emit(result)
    
    def cancel(self):
        """Cancel the optimal wipe operation"""
        self.is_cancelled = True

# ADD THESE METHODS to the MainWindow class in main_gui.py:


class WipeWorkerThread(QThread):
    """Worker thread for data wiping operations"""
    
    progress_updated = pyqtSignal(int)  # Progress percentage
    status_updated = pyqtSignal(str)    # Status message
    wipe_completed = pyqtSignal(object) # WipeResult object
    
    def __init__(self, engine: SecureWipeEngine, device_path: str, wipe_level: WipeLevel):
        super().__init__()
        self.engine = engine
        self.device_path = device_path
        self.wipe_level = wipe_level
        self.is_cancelled = False
    
    def run(self):
        """Execute the wipe operation"""
        try:
            def progress_callback(percentage):
                if not self.is_cancelled:
                    self.progress_updated.emit(int(percentage))
                    self.status_updated.emit(f"Wiping... {percentage:.1f}%")
            
            self.status_updated.emit("Starting wipe operation...")
            result = self.engine.wipe_device(
                self.device_path, 
                self.wipe_level, 
                progress_callback
            )
            self.wipe_completed.emit(result)
            
        except Exception as e:
            result = WipeResult(
                success=False,
                device_path=self.device_path,
                wipe_level=self.wipe_level,
                duration_seconds=0,
                error_message=str(e)
            )
            self.wipe_completed.emit(result)
    
    def cancel(self):
        """Cancel the wipe operation"""
        self.is_cancelled = True

class DeviceSelectionDialog(QDialog):
    """Dialog for selecting devices and wipe level"""
    
    def __init__(self, devices: List[Dict], parent=None):
        super().__init__(parent)
        self.devices = devices
        self.selected_device = None
        self.selected_level = WipeLevel.PURGE
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Select Device and Wipe Level")
        self.setModal(True)
        self.resize(600, 400)
        
        layout = QVBoxLayout()
        
        # Device selection
        device_group = QGroupBox("Select Storage Device")
        device_layout = QVBoxLayout()
        
        self.device_list = QListWidget()
        for device in self.devices:
            item_text = f"{device['path']} - {device.get('size_gb', 0):.1f} GB ({device.get('device_type', 'unknown')})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, device)
            self.device_list.addItem(item)
        
        self.device_list.currentItemChanged.connect(self.on_device_selected)
        device_layout.addWidget(self.device_list)
        device_group.setLayout(device_layout)
        layout.addWidget(device_group)
        
        # Wipe level selection
        level_group = QGroupBox("Select NIST Wipe Level")
        level_layout = QVBoxLayout()
        
        self.level_combo = QComboBox()
        self.level_combo.addItem("Clear - Single pass overwrite (Consumer devices)", WipeLevel.CLEAR)
        self.level_combo.addItem("Purge - Multi-pass + secure erase (Enterprise)", WipeLevel.PURGE)
        self.level_combo.addItem("Destroy - Physical destruction guidance", WipeLevel.DESTROY)
        self.level_combo.setCurrentIndex(1)  # Default to Purge
        self.level_combo.currentIndexChanged.connect(self.on_level_changed)
        
        level_layout.addWidget(self.level_combo)
        
        # Level description
        self.level_description = QLabel()
        self.update_level_description()
        level_layout.addWidget(self.level_description)
        
        level_group.setLayout(level_layout)
        layout.addWidget(level_group)
        
        # Device info
        self.device_info = QTextEdit()
        self.device_info.setMaximumHeight(100)
        self.device_info.setReadOnly(True)
        layout.addWidget(QLabel("Device Information:"))
        layout.addWidget(self.device_info)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def on_device_selected(self, current, previous):
        """Handle device selection"""
        if current:
            self.selected_device = current.data(Qt.UserRole)
            
            # Update device info
            info = f"Path: {self.selected_device['path']}\\n"
            info += f"Size: {self.selected_device.get('size_gb', 0):.2f} GB\\n"
            info += f"Type: {self.selected_device.get('device_type', 'unknown')}\\n"
            info += f"File System: {self.selected_device.get('file_system', 'unknown')}\\n"
            
            if self.selected_device.get('mount_point'):
                info += f"Mount Point: {self.selected_device['mount_point']}\\n"
            
            self.device_info.setText(info)
    
    def on_level_changed(self, index):
        """Handle wipe level change"""
        self.selected_level = self.level_combo.itemData(index)
        self.update_level_description()
    
    def update_level_description(self):
        """Update the wipe level description"""
        descriptions = {
            WipeLevel.CLEAR: "Single-pass overwrite with zeros. Suitable for non-sensitive data on consumer devices.",
            WipeLevel.PURGE: "Multi-pass overwrite + hardware secure erase + hidden area clearing. Suitable for enterprise and confidential data.",
            WipeLevel.DESTROY: "Provides guidance for physical destruction. Required for top secret/classified data."
        }
        
        self.level_description.setText(descriptions.get(self.selected_level, ""))
        self.level_description.setWordWrap(True)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.engine = None
        self.devices = []
        self.wipe_thread = None
        self.optimal_wipe_thread = None  # <-- initialize optimal wipe thread handle
        self.init_ui()
        self.init_engine()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("SecureWipe India - Secure Data Sanitization")
        self.setGeometry(100, 100, 1000, 700)
        
        # Set application icon (if available)
        try:
            self.setWindowIcon(QIcon("assets/icon.png"))
        except:
            pass
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        # Warning banner
        warning_label = QLabel("⚠️  WARNING: Wiping a device will PERMANENTLY ERASE ALL DATA.\nMake sure you select the correct physical device before proceeding.")
        warning_label.setStyleSheet("background-color: #ffcccc; color: #800000; padding: 10px; border: 1px solid #800000;")
        warning_label.setWordWrap(True)
        main_layout.addWidget(warning_label)
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Content area with tabs
        self.tab_widget = QTabWidget()
        
        # Main tab
        main_tab = self.create_main_tab()
        self.tab_widget.addTab(main_tab, "Data Wipe")
        
        # Device info tab
        device_tab = self.create_device_tab()
        self.tab_widget.addTab(device_tab, "Device Information")
        
        # Certificates tab
        cert_tab = self.create_certificates_tab()
        self.tab_widget.addTab(cert_tab, "Certificates")
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.statusBar().showMessage("Ready - Select a device to begin")
        
        central_widget.setLayout(main_layout)
    
    def create_header(self) -> QWidget:
        """Create application header"""
        header = QFrame()
        header.setFrameStyle(QFrame.StyledPanel)
        header.setStyleSheet("background-color: #1976D2; color: white; padding: 10px;")
        
        layout = QHBoxLayout()
        
        # Logo and title
        title_label = QLabel("SecureWipe India")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        subtitle_label = QLabel("NIST 800-88 Compliant Data Sanitization")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_label.setFont(subtitle_font)
        
        title_layout = QVBoxLayout()
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Indian flag colors indicator
        flag_widget = QWidget()
        flag_widget.setFixedSize(60, 40)
        flag_widget.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                stop:0 #FF9933, stop:0.33 #FF9933,
                stop:0.33 #FFFFFF, stop:0.66 #FFFFFF,
                stop:0.66 #138808, stop:1 #138808);
        """)
        layout.addWidget(flag_widget)
        
        header.setLayout(layout)
        return header
    
    def create_main_tab(self) -> QWidget:
        """Create the main wipe operation tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Device selection area
        device_group = QGroupBox("Storage Devices")
        device_layout = QVBoxLayout()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Devices")
        refresh_btn.clicked.connect(self.refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        # Device list
        self.device_table = QTableWidget()
        # Add a Physical ID column and Optimal capability column to show device serial/model and optimal method
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(["Device", "Physical ID", "Size", "Type", "Status", "Optimal"])
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.currentCellChanged.connect(self.on_device_selection_changed)
        device_layout.addWidget(self.device_table)
        
        device_group.setLayout(device_layout)
        layout.addWidget(device_group)
        
        # Operation controls
        control_group = QGroupBox("Wipe Operation")
        control_layout = QVBoxLayout()
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.wipe_btn = QPushButton("🗑️ Start Secure Wipe")
        self.wipe_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 10px; }")
        self.wipe_btn.clicked.connect(self.start_wipe)
        
        # NEW OPTIMAL WIPE BUTTON
        self.optimal_wipe_btn = QPushButton("🚀 Optimal Fast Wipe")
        self.optimal_wipe_btn.setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; padding: 10px; }")
        self.optimal_wipe_btn.clicked.connect(self.start_optimal_wipe)
        
        self.cancel_btn = QPushButton("⏹️ Cancel Operation")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_wipe)
        
        button_layout.addWidget(self.wipe_btn)
        button_layout.addWidget(self.optimal_wipe_btn)  # NEW BUTTON
        button_layout.addWidget(self.cancel_btn)
        button_layout.addStretch()
        
        control_layout.addLayout(button_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)
        
        # Status
        self.status_label = QLabel("Select a device to begin")
        control_layout.addWidget(self.status_label)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Log output
        log_group = QGroupBox("Operation Log")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(200)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_device_tab(self) -> QWidget:
        """Create device information tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        self.device_info_text = QTextEdit()
        self.device_info_text.setReadOnly(True)
        layout.addWidget(self.device_info_text)
        
        widget.setLayout(layout)
        return widget
    
    def create_certificates_tab(self) -> QWidget:
        """Create certificates management tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Certificate list
        cert_group = QGroupBox("Generated Certificates")
        cert_layout = QVBoxLayout()
        
        self.cert_table = QTableWidget()
        self.cert_table.setColumnCount(4)
        self.cert_table.setHorizontalHeaderLabels(["Certificate ID", "Device", "Date", "Status"])
        cert_layout.addWidget(self.cert_table)
        
        # Certificate actions
        cert_button_layout = QHBoxLayout()
        
        view_cert_btn = QPushButton("View Certificate")
        view_cert_btn.clicked.connect(self.view_certificate)
        
        verify_cert_btn = QPushButton("Verify Certificate")
        verify_cert_btn.clicked.connect(self.verify_certificate)
        
        cert_button_layout.addWidget(view_cert_btn)
        cert_button_layout.addWidget(verify_cert_btn)
        cert_button_layout.addStretch()
        
        cert_layout.addLayout(cert_button_layout)
        cert_group.setLayout(cert_layout)
        layout.addWidget(cert_group)
        
        widget.setLayout(layout)
        return widget
    
    def init_engine(self):
        """Initialize the SecureWipe engine"""
        try:
            self.engine = SecureWipeEngine()
            self.log_message("SecureWipe engine initialized successfully")
            self.refresh_devices()
        except Exception as e:
            self.log_message(f"Failed to initialize engine: {e}")
            QMessageBox.critical(self, "Error", f"Failed to initialize SecureWipe engine:\\n{e}")
    
    def refresh_devices(self):
        """Refresh the list of storage devices"""
        try:
            self.log_message("Scanning for storage devices...")
            self.devices = self.engine.detect_storage_devices()
            self.update_device_table()
            self.log_message(f"Found {len(self.devices)} storage devices")
        except Exception as e:
            self.log_message(f"Device scan failed: {e}")
            QMessageBox.warning(self, "Warning", f"Failed to scan devices:\\n{e}")
    
    def update_device_table(self):
        """Update the device table with current devices"""
        self.device_table.setRowCount(len(self.devices))
        for row, device in enumerate(self.devices):
            # Device path
            self.device_table.setItem(row, 0, QTableWidgetItem(device.get('path', '')))

            # Physical ID (serial or model)
            physical_id = device.get('serial') or device.get('model') or 'Unknown'
            self.device_table.setItem(row, 1, QTableWidgetItem(physical_id))

            # Size
            size_gb = device.get('size_gb', 0)
            size_text = f"{size_gb:.2f} GB" if size_gb > 0 else "Unknown"
            self.device_table.setItem(row, 2, QTableWidgetItem(size_text))

            # Type
            device_type = device.get('device_type', 'unknown').title()
            self.device_table.setItem(row, 3, QTableWidgetItem(device_type))

            # Status
            status = "Ready" if device.get('mount_point') else "Unmounted"
            self.device_table.setItem(row, 4, QTableWidgetItem(status))

            # Optimal capability detection placeholder (will be filled by detect call)
            optimal_text = device.get('optimal_method_display', 'Unknown')
            item_opt = QTableWidgetItem(optimal_text)
            item_opt.setFlags(item_opt.flags() & ~Qt.ItemIsEditable)
            self.device_table.setItem(row, 5, item_opt)
        
        self.device_table.resizeColumnsToContents()

        # After updating table, run optimal detection for each device in background (non-blocking)
        QTimer.singleShot(100, self.detect_optimal_for_devices)

    def detect_optimal_for_devices(self):
        """Detect optimal method for each device and update the table UI."""
        try:
            optimal = OptimalSecureErase()
        except Exception:
            # If OptimalSecureErase can't initialize, mark all as Unknown
            for row, device in enumerate(self.devices):
                self.device_table.setItem(row, 5, QTableWidgetItem('Unknown'))
            return

        for row, device in enumerate(self.devices):
            try:
                method, info = optimal.detect_optimal_method(device.get('path', ''), device)
                device['optimal_method'] = method
                display = method.value.replace('_', ' ').title()
                device['optimal_method_display'] = display
                self.device_table.setItem(row, 5, QTableWidgetItem(display))
            except Exception as e:
                self.device_table.setItem(row, 5, QTableWidgetItem('Unknown'))

        # Ensure optimal button state reflects selected device
        self.update_optimal_button_state()

    def on_device_selection_changed(self, current_row, current_col, previous_row, previous_col):
        """Enable/disable buttons based on the currently selected device"""
        # currentCellChanged gives row/col; guard for -1
        row = current_row
        if row is None or row < 0:
            self.wipe_btn.setEnabled(True)
            self.optimal_wipe_btn.setEnabled(False)
            return
        # Use the devices array if available
        if 0 <= row < len(self.devices):
            device = self.devices[row]
            # Enable optimal button only if the device has a detected optimal method other than FALLBACK_OVERWRITE
            method = device.get('optimal_method')
            if method and getattr(method, 'value', None) and method != SecureEraseMethod.FALLBACK_OVERWRITE:
                self.optimal_wipe_btn.setEnabled(True)
            else:
                self.optimal_wipe_btn.setEnabled(False)

    def update_optimal_button_state(self):
        """Update optimal button enabled state based on current selection"""
        row = self.device_table.currentRow()
        if row < 0 or row >= len(self.devices):
            self.optimal_wipe_btn.setEnabled(False)
            return

        device = self.devices[row]
        method = device.get('optimal_method')
        if method and method != SecureEraseMethod.FALLBACK_OVERWRITE:
            self.optimal_wipe_btn.setEnabled(True)
        else:
            self.optimal_wipe_btn.setEnabled(False)
    
    def start_wipe(self):
        """Start the wipe operation"""
        try:
            # Get selected device
            current_row = self.device_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a device to wipe")
                return
            
            selected_device = self.devices[current_row]
            
            # Show device selection dialog
            dialog = DeviceSelectionDialog([selected_device], self)
            if dialog.exec_() != QDialog.Accepted:
                return
            
            device_path = dialog.selected_device['path']
            wipe_level = dialog.selected_level
            
            # Confirmation dialog
            if not self.confirm_wipe(device_path, wipe_level):
                return

            # Create a lock file to ensure deliberate target (writes config/lock.json)
            physical = dialog.selected_device.get('physical_device') or dialog.selected_device.get('serial') or ''
            if not self.create_lock_file(device_path, physical):
                QMessageBox.critical(self, "Lock Error", "Failed to create lock file. Aborting.")
                return
            
            # Start wipe thread
            self.wipe_thread = WipeWorkerThread(self.engine, device_path, wipe_level)
            self.wipe_thread.progress_updated.connect(self.update_progress)
            self.wipe_thread.status_updated.connect(self.update_status)
            self.wipe_thread.wipe_completed.connect(self.wipe_completed)
            
            # Update UI
            self.wipe_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            self.wipe_thread.start()
            self.log_message(f"Started {wipe_level.value} wipe on {device_path}")
            
        except Exception as e:
            self.log_message(f"Failed to start wipe: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start wipe operation:\\n{e}")

    def create_lock_file(self, path: str, physical_device: str) -> bool:
        """Write a lock file to config/lock.json to mark the intended wipe target."""
        try:
            os.makedirs('config', exist_ok=True)
            lock = {
                'path': path,
                'physical_device': physical_device,
                'created_by': os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
                'created_at': time.time()
            }
            with open(os.path.join('config', 'lock.json'), 'w') as f:
                json.dump(lock, f, indent=2)
            self.log_message(f"Lock file created for {path} ({physical_device})")
            return True
        except Exception as e:
            self.log_message(f"Failed to write lock file: {e}")
            return False
    
    def confirm_wipe(self, device_path: str, wipe_level: WipeLevel) -> bool:
        """Show confirmation dialog for wipe operation"""
        # First confirm with Yes/No
        message = f"WARNING: This operation will permanently destroy all data on the selected device.\n\nDevice: {device_path}\nWipe Level: {wipe_level.value.upper()}\n\nThis action cannot be undone."
        reply = QMessageBox.question(
            self,
            "Confirm Data Wipe",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return False

        # Second confirm: require typing CONFIRM to proceed
        text, ok = QInputDialog.getText(self, "Type CONFIRM to proceed", f"Type 'CONFIRM' to permanently wipe {device_path}:")
        if not ok:
            return False

        if text.strip().upper() != "CONFIRM":
            QMessageBox.warning(self, "Confirmation Failed", "You did not type CONFIRM. Operation cancelled.")
            return False

        # Third confirm: checkbox acknowledgment dialog
        confirm_dialog = QMessageBox(self)
        confirm_dialog.setIcon(QMessageBox.Warning)
        confirm_dialog.setWindowTitle("Final Confirmation")
        confirm_dialog.setText("Final check: Are you completely sure you want to proceed with this irreversible operation?")
        confirm_dialog.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        final = confirm_dialog.exec_()
        return final == QMessageBox.Ok

    def start_optimal_wipe(self):
        """Start optimal secure erase operation"""
        try:
            current_row = self.device_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a device to wipe")
                return

            selected_device = self.devices[current_row]

            dialog = OptimalEraseDialog(selected_device, self)
            if dialog.exec_() != QDialog.Accepted:
                return

            device_path = selected_device['path']
            optimal_method = dialog.selected_method

            if not self.confirm_optimal_wipe(device_path, optimal_method):
                return

            # Start optimal wipe thread
            self.optimal_wipe_thread = OptimalWipeWorkerThread(device_path, optimal_method)
            self.optimal_wipe_thread.progress_updated.connect(self.update_progress_with_message)
            self.optimal_wipe_thread.status_updated.connect(self.update_status)
            self.optimal_wipe_thread.wipe_completed.connect(self.optimal_wipe_completed)

            # Update UI
            self.wipe_btn.setEnabled(False)
            self.optimal_wipe_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            self.optimal_wipe_thread.start()
            self.log_message(f"Started optimal {optimal_method.value} on {device_path}")

        except Exception as e:
            self.log_message(f"Failed to start optimal wipe: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start optimal wipe:\n{e}")

    def confirm_optimal_wipe(self, device_path: str, method: SecureEraseMethod) -> bool:
        """Show confirmation dialog for optimal wipe"""
        method_name = method.value.replace('_', ' ').title()

        message = f"""⚡ OPTIMAL SECURE ERASE CONFIRMATION

Device: {device_path}
Method: {method_name}

🚀 This operation will use hardware-level commands for maximum speed and security.
⚠️  ALL DATA will be PERMANENTLY DESTROYED and CANNOT BE RECOVERED.
🔥 This is MUCH FASTER than traditional overwrite methods.

Are you absolutely sure you want to proceed?"""

        reply = QMessageBox.question(
            self,
            "Confirm Optimal Secure Erase",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        return reply == QMessageBox.Yes

    def optimal_wipe_completed(self, result: Dict):
        """Handle optimal wipe completion"""
        # Reset UI
        self.wipe_btn.setEnabled(True)
        self.optimal_wipe_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        if result.get("success"):
            method_used = result.get("method_used")
            method_name = method_used.value.replace('_', ' ').title() if method_used else "Unknown"
            duration = result.get("duration", 0)

            self.log_message(f"Optimal wipe completed successfully in {duration:.1f}s using {method_name}")

            QMessageBox.information(
                self,
                "Optimal Wipe Completed",
                f"🚀 Optimal secure erase completed successfully!\n\nMethod: {method_name}\nDuration: {duration:.1f} seconds\n\nYour device has been securely wiped using hardware-level commands."
            )
        else:
            error_msg = result.get("error", "Unknown error")
            self.log_message(f"Optimal wipe failed: {error_msg}")
            QMessageBox.critical(
                self,
                "Optimal Wipe Failed",
                f"Optimal secure erase failed:\n\n{error_msg}\n\nYou may try the standard wipe method as a fallback."
            )

        self.update_status("Ready")
        self.optimal_wipe_thread = None

    def update_progress_with_message(self, percentage: int, message: str):
        """Update progress bar and status with message"""
        self.progress_bar.setValue(percentage)
        if message:
            self.status_label.setText(message)
            self.statusBar().showMessage(message)
    
    def cancel_wipe(self):
        """Cancel the current wipe operation"""
        cancelled = False
        if self.wipe_thread:
            self.wipe_thread.cancel()
            self.log_message("Wipe operation cancelled by user")
            cancelled = True

        if self.optimal_wipe_thread:
            self.optimal_wipe_thread.cancel()
            self.log_message("Optimal wipe operation cancelled by user")
            cancelled = True

        if not cancelled:
            self.log_message("No running wipe operation to cancel")
    
    def update_progress(self, percentage: int):
        """Update the progress bar"""
        self.progress_bar.setValue(percentage)
    
    def update_status(self, status: str):
        """Update the status label"""
        self.status_label.setText(status)
        self.statusBar().showMessage(status)
    
    def wipe_completed(self, result: WipeResult):
        """Handle wipe completion"""
        # Reset UI
        self.wipe_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        if result.success:
            self.log_message(f"Wipe completed successfully in {result.duration_seconds:.1f}s")
            self.log_message(f"Certificate generated: {result.certificate_path}")
            
            QMessageBox.information(
                self,
                "Wipe Completed",
                f"Data wipe completed successfully!\\n\\nDevice: {result.device_path}\\nLevel: {result.wipe_level.value}\\nDuration: {result.duration_seconds:.1f} seconds\\n\\nCertificate: {result.certificate_path}"
            )
        else:
            self.log_message(f"Wipe failed: {result.error_message}")
            QMessageBox.critical(
                self,
                "Wipe Failed",
                f"Data wipe operation failed:\\n\\n{result.error_message}"
            )
        
        self.update_status("Ready")
        self.wipe_thread = None
    
    def view_certificate(self):
        """View a generated certificate"""
        # Implementation for viewing certificates
        QMessageBox.information(self, "View Certificate", "Certificate viewing feature coming soon!")
    
    def verify_certificate(self):
        """Verify a certificate"""
        # Implementation for certificate verification
        QMessageBox.information(self, "Verify Certificate", "Certificate verification feature coming soon!")
    
    def log_message(self, message: str):
        """Add message to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_text.append(log_entry)
        
        # Keep log size manageable
        if self.log_text.document().lineCount() > 1000:
            cursor = self.log_text.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 100)
            cursor.removeSelectedText()

def main():
    """Main application entry point"""
    if not PYQT_AVAILABLE:
        print("PyQt5 is required for the GUI application.")
        print("Install with: pip install PyQt5")
        return 1
    
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("SecureWipe India")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Government of India")
    
    # Apply dark theme (optional)
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())