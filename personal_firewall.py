#!/usr/bin/env python3
import sys
import os
import logging
import platform
import threading
import time
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, 
    QMessageBox, QLabel, QStatusBar, QLineEdit, QCheckBox,
    QSystemTrayIcon, QMenu, QAction, QDialog, QProgressDialog,
    QFileDialog, QTabWidget, QToolBar, QComboBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QIcon, QPixmap

from firewall_factory import get_firewall
from config_manager import ConfigManager
from privilege_helper import is_admin, restart_as_admin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'personal_firewall.log'
        ))
    ]
)
logger = logging.getLogger(__name__)

class RefreshWorker(QThread):
    """Worker thread for refreshing application list"""
    finished = pyqtSignal(list)
    progress = pyqtSignal(int)
    
    def __init__(self, firewall):
        super().__init__()
        self.firewall = firewall
        
    def run(self):
        try:
            # Get applications with network access
            applications = self.firewall.get_all_applications()
            self.finished.emit(applications)
        except Exception as e:
            logger.error(f"Error in refresh worker: {e}")
            self.finished.emit([])


class ApplicationTable(QTableWidget):
    """Custom table widget for displaying applications"""
    
    status_changed = pyqtSignal(str, bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        # Set up the table
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["Application", "Path", "Status"])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
    
    def update_applications(self, applications):
        """Update the table with a list of applications"""
        self.setRowCount(0)  # Clear the table
        
        for i, app in enumerate(applications):
            self.insertRow(i)
            self.setItem(i, 0, QTableWidgetItem(app.get('name', 'Unknown')))
            self.setItem(i, 1, QTableWidgetItem(app.get('path', '')))
            
            # Create a checkbox for the status
            checkbox = QCheckBox()
            checkbox.setChecked(not app.get('blocked', False))
            checkbox.stateChanged.connect(lambda state, path=app.get('path'): 
                                          self.status_changed.emit(path, state == Qt.Checked))
            
            # Add the checkbox to the table
            self.setCellWidget(i, 2, checkbox)
            
    def filter_applications(self, search_text):
        """Filter the table based on search text"""
        search_text = search_text.lower()
        
        for i in range(self.rowCount()):
            row_hidden = True
            
            # Check if the search text is in any column
            for j in range(self.columnCount()):
                item = self.item(i, j)
                if item and search_text in item.text().lower():
                    row_hidden = False
                    break
            
            # Show/hide the row
            self.setRowHidden(i, row_hidden)


class MainWindow(QMainWindow):
    """Main window for the Personal Firewall application"""
    
    def __init__(self):
        super().__init__()
        
        # Check for admin privileges
        if not is_admin():
            QMessageBox.warning(
                None, 
                "Administrator Privileges Required", 
                "This application requires administrator privileges to function properly. "
                "Please click OK to restart with elevated privileges."
            )
            restart_as_admin()
            sys.exit(0)
        
        # Initialize components
        try:
            self.firewall = get_firewall()
        except (ImportError, NotImplementedError) as e:
            QMessageBox.critical(
                None, 
                "Firewall Error", 
                f"Failed to initialize firewall: {e}\n\n"
                f"The application cannot continue."
            )
            sys.exit(1)
            
        self.config_manager = ConfigManager()
        
        # Set up the UI
        self.setup_ui()
        
        # Load saved applications
        self.blocked_apps = self.config_manager.blocked_apps
        
        # Set up refresh timer
        refresh_interval = self.config_manager.get_config_value("refresh_interval", 60)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_applications)
        self.refresh_timer.start(refresh_interval * 1000)
        
        # Initial refresh
        self.refresh_applications()
    
    def setup_ui(self):
        """Set up the user interface"""
        # Configure the main window
        self.setWindowTitle("Personal Firewall")
        self.setMinimumSize(800, 600)
        
        # Central widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create toolbar
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        
        # Refresh button
        refresh_action = QAction("Refresh", self)
        refresh_action.setStatusTip("Refresh the list of applications")
        refresh_action.triggered.connect(self.refresh_applications)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        # Add Settings action
        settings_action = QAction("Settings", self)
        settings_action.setStatusTip("Open settings dialog")
        settings_action.triggered.connect(self.open_settings)
        toolbar.addAction(settings_action)
        
        # Add About action
        about_action = QAction("About", self)
        about_action.setStatusTip("Show information about this application")
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        
        self.addToolBar(toolbar)
        
        # Create tab widget for organizing sections
        tab_widget = QTabWidget()
        
        # Applications tab
        apps_widget = QWidget()
        apps_layout = QVBoxLayout(apps_widget)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search for applications...")
        self.search_input.textChanged.connect(self.filter_applications)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        apps_layout.addLayout(search_layout)
        
        # Application table
        self.app_table = ApplicationTable()
        self.app_table.status_changed.connect(self.toggle_application_status)
        apps_layout.addWidget(self.app_table)
        
        # Add applications tab
        tab_widget.addTab(apps_widget, "Applications")
        
        # Active Connections tab (stub for future implementation)
        connections_widget = QWidget()
        connections_layout = QVBoxLayout(connections_widget)
        connections_layout.addWidget(QLabel("Active network connections will be shown here in a future update."))
        tab_widget.addTab(connections_widget, "Active Connections")
        
        # Add tab widget to main layout
        main_layout.addWidget(tab_widget)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Set the central widget
        self.setCentralWidget(central_widget)
        
        # System tray icon
        self.setup_tray_icon()
    
    def setup_tray_icon(self):
        """Set up the system tray icon"""
        # Create the tray icon menu
        tray_menu = QMenu()
        
        # Add actions to the menu
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_applications)
        tray_menu.addAction(refresh_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        # Create the tray icon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setContextMenu(tray_menu)
        
        # Set the icon (placeholder icon, you should replace with an actual icon)
        # self.tray_icon.setIcon(QIcon("icon.png"))
        
        # Show the tray icon
        self.tray_icon.show()
        
        # Connect the activated signal
        self.tray_icon.activated.connect(self.tray_icon_activated)
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()
    
    def refresh_applications(self):
        """Refresh the list of applications"""
        self.status_bar.showMessage("Refreshing applications...")
        
        # Create a progress dialog
        progress = QProgressDialog("Refreshing applications...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setCancelButton(None)
        progress.setMinimumDuration(500)  # Only show for operations taking longer than 500ms
        
        # Start the worker thread
        self.worker = RefreshWorker(self.firewall)
        self.worker.finished.connect(self.update_application_list)
        self.worker.finished.connect(progress.close)
        self.worker.start()
    
    def update_application_list(self, applications):
        """Update the application list with the results"""
        # Apply any saved blocked status
        for app in applications:
            if app.get("path") in self.blocked_apps:
                app["blocked"] = True
                
        # Update the table
        self.app_table.update_applications(applications)
        
        # Update status bar
        self.status_bar.showMessage(f"Found {len(applications)} applications with network access", 5000)
    
    def filter_applications(self):
        """Filter the applications based on search input"""
        self.app_table.filter_applications(self.search_input.text())
    
    def toggle_application_status(self, app_path, allowed):
        """Toggle the blocking status of an application"""
        try:
            if allowed:
                # Unblock the application
                success = self.firewall.unblock_application(app_path)
                if success:
                    self.status_bar.showMessage(f"Unblocked {Path(app_path).name}", 5000)
                    if app_path in self.blocked_apps:
                        self.config_manager.remove_blocked_app(app_path)
                        self.blocked_apps = self.config_manager.blocked_apps
                else:
                    self.status_bar.showMessage(f"Failed to unblock {Path(app_path).name}", 5000)
            else:
                # Block the application
                success = self.firewall.block_application(app_path)
                if success:
                    self.status_bar.showMessage(f"Blocked {Path(app_path).name}", 5000)
                    self.config_manager.add_blocked_app(app_path)
                    self.blocked_apps = self.config_manager.blocked_apps
                else:
                    self.status_bar.showMessage(f"Failed to block {Path(app_path).name}", 5000)
        except Exception as e:
            logger.error(f"Error toggling application status: {e}")
            QMessageBox.warning(
                self, 
                "Error", 
                f"Failed to change application status: {e}"
            )
    
    def open_settings(self):
        """Open the settings dialog"""
        # Create a simple settings dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setMinimumSize(400, 300)
        
        layout = QVBoxLayout(dialog)
        
        # Refresh interval
        refresh_layout = QHBoxLayout()
        refresh_label = QLabel("Refresh Interval (seconds):")
        refresh_combo = QComboBox()
        refresh_combo.addItems(["30", "60", "120", "300", "600"])
        refresh_combo.setCurrentText(str(self.config_manager.get_config_value("refresh_interval", 60)))
        refresh_layout.addWidget(refresh_label)
        refresh_layout.addWidget(refresh_combo)
        layout.addLayout(refresh_layout)
        
        # Notifications
        notifications_check = QCheckBox("Show notifications")
        notifications_check.setChecked(self.config_manager.get_config_value("show_notifications", True))
        layout.addWidget(notifications_check)
        
        # Startup
        startup_check = QCheckBox("Start with system")
        startup_check.setChecked(self.config_manager.get_config_value("startup_enabled", False))
        layout.addWidget(startup_check)
        
        # Auto-block
        autoblock_check = QCheckBox("Automatically block new applications")
        autoblock_check.setChecked(self.config_manager.get_config_value("auto_block_new_apps", False))
        layout.addWidget(autoblock_check)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        save_button = QPushButton("Save")
        save_button.clicked.connect(dialog.accept)
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(save_button)
        layout.addLayout(buttons_layout)
        
        # Show the dialog
        if dialog.exec_() == QDialog.Accepted:
            # Save settings
            self.config_manager.set_config_value("refresh_interval", int(refresh_combo.currentText()))
            self.config_manager.set_config_value("show_notifications", notifications_check.isChecked())
            self.config_manager.set_config_value("startup_enabled", startup_check.isChecked())
            self.config_manager.set_config_value("auto_block_new_apps", autoblock_check.isChecked())
            
            # Update timer
            self.refresh_timer.setInterval(int(refresh_combo.currentText()) * 1000)
            
            # Update startup setting
            self._update_startup_setting(startup_check.isChecked())
    
    def _update_startup_setting(self, enabled):
        """Update the startup setting in the system"""
        # This is platform-specific and would need implementation
        pass  # Placeholder for actual implementation
    
    def show_about(self):
        """Show the about dialog"""
        QMessageBox.about(
            self,
            "About Personal Firewall",
            f"<h1>Personal Firewall</h1>"
            f"<p>Version 1.0.0</p>"
            f"<p>A cross-platform GUI-based personal firewall that allows users to "
            f"block applications from accessing the internet.</p>"
            f"<p>Platform: {platform.system()} {platform.release()}</p>"
            f"<p>Python: {platform.python_version()}</p>"
            f"<p>&copy; 2025</p>"
        )
    
    def closeEvent(self, event):
        """Handle the window close event"""
        if self.config_manager.get_config_value("show_notifications", True):
            # Minimize to tray instead of closing
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "Personal Firewall",
                "The application has been minimized to the system tray. "
                "Double-click the tray icon to show the window again.",
                QSystemTrayIcon.Information,
                2000
            )
        else:
            # Actually close the application
            event.accept()


if __name__ == "__main__":
    # Create the application
    app = QApplication(sys.argv)
    
    # Set application details
    app.setApplicationName("Personal Firewall")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Personal Firewall")
    
    # Create the main window
    window = MainWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())