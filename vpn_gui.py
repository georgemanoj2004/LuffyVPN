import os
import subprocess
import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QListWidget, QMessageBox, QFileDialog, QLabel, QLineEdit, QInputDialog,
    QDialog, QFormLayout, QComboBox, QApplication, QTabWidget, QTextEdit
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
import urllib.request
import urllib.error

PROFILES_FILE = "vpn_profiles.json"
SETTINGS_FILE = "vpn_settings.json"


class CredentialsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Credentials")
        self.setModal(True)

        layout = QFormLayout()

        self.sudo_password = QLineEdit()
        self.sudo_password.setEchoMode(QLineEdit.Password)
        layout.addRow("System Password:", self.sudo_password)

        # Some callers (VPN) want VPN username/password too; others (macchanger) only need sudo.
        self.vpn_username = QLineEdit()
        layout.addRow("VPN Username (optional):", self.vpn_username)

        self.vpn_password = QLineEdit()
        self.vpn_password.setEchoMode(QLineEdit.Password)
        layout.addRow("VPN Password (optional):", self.vpn_password)

        buttons = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        buttons.addWidget(self.ok_button)
        buttons.addWidget(self.cancel_button)

        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        layout.addRow(buttons)
        self.setLayout(layout)

    def setup_tab_order_and_enter_behavior(self):
        # Optional explicit tab order
        self.setTabOrder(self.sudo_password, self.vpn_username)
        self.setTabOrder(self.vpn_username, self.vpn_password)
        self.setTabOrder(self.vpn_password, self.ok_button)
        self.setTabOrder(self.ok_button, self.cancel_button)

        # Connect Return/Enter behavior
        self.sudo_password.returnPressed.connect(lambda: self.vpn_username.setFocus())
        self.vpn_username.returnPressed.connect(lambda: self.vpn_password.setFocus())
        self.vpn_password.returnPressed.connect(lambda: self.ok_button.setFocus())

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            fw = self.focusWidget()
            if fw is self.sudo_password:
                self.vpn_username.setFocus()
                return
            if fw is self.vpn_username:
                self.vpn_password.setFocus()
                return
            if fw is self.vpn_password:
                self.ok_button.setFocus()
                return
            if fw is self.ok_button:
                self.accept()
                return
            if fw is self.cancel_button:
                self.reject()
                return
        super().keyPressEvent(event)


class SettingsDialog(QDialog):
    """
    Settings dialog to pick a theme.
    Themes:
      - Default (uses the default colors)
      - Dark (white text)
      - Dark (green text)
    """
    def __init__(self, parent=None, current_theme="default"):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.parent = parent

        layout = QFormLayout()

        self.theme_combo = QComboBox()
        # internal keys: default, dark_white, dark_green
        self.theme_combo.addItem("White", "default")
        self.theme_combo.addItem("Dark — white text", "dark_white")
        self.theme_combo.addItem("Dark — green text", "dark_green")

        # set current index by matching data
        for i in range(self.theme_combo.count()):
            if self.theme_combo.itemData(i) == current_theme:
                self.theme_combo.setCurrentIndex(i)
                break

        layout.addRow("Theme:", self.theme_combo)

        # Buttons
        buttons = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        close_btn = QPushButton("Close")
        buttons.addWidget(apply_btn)
        buttons.addWidget(close_btn)

        apply_btn.clicked.connect(self.apply_settings)
        close_btn.clicked.connect(self.accept)

        layout.addRow(buttons)
        self.setLayout(layout)

        # Live preview when changed
        self.theme_combo.currentIndexChanged.connect(self._live_preview)

    def _selected_theme(self):
        return self.theme_combo.currentData()

    def _live_preview(self, *args):
        if not self.parent:
            return
        theme = self._selected_theme()
        self.parent.apply_theme(theme, save=False)

    def apply_settings(self):
        if not self.parent:
            return
        theme = self._selected_theme()
        self.parent.apply_theme(theme, save=True)
        QMessageBox.information(self, "Settings", "Theme applied and saved.")


class VPNOutputReader(QThread):
    line_emitted = pyqtSignal(str)
    connected = pyqtSignal()
    disconnected = pyqtSignal()

    def __init__(self, process):
        super().__init__()
        self.process = process
        self._running = True

    def run(self):
        # Read lines from process.stdout until it ends
        try:
            while self._running:
                if self.process is None:
                    break
                line = self.process.stdout.readline()
                # If stdout returned empty and process has exited => disconnected
                if line == "" and self.process.poll() is not None:
                    self.disconnected.emit()
                    break
                if not line:
                    # avoid busy loop
                    self.msleep(100)
                    continue
                text = line.strip()
                self.line_emitted.emit(text)
                # Typical OpenVPN success message
                if "Initialization Sequence Completed" in text:
                    self.connected.emit()
                # Optionally detect disconnection messages
                if "SIGTERM" in text or "EXITING" in text or "AUTH_FAILED" in text:
                    # emit disconnected if we see explicit termination/auth failure lines
                    self.disconnected.emit()
        except Exception:
            pass

    def stop(self):
        self._running = False
        try:
            self.wait(1000)
        except Exception:
            pass


class VPNMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LuffyVPN")
        self.setGeometry(300, 200, 700, 560)
        self.vpn_process = None
        self.output_thread = None

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Load saved settings (theme)
        self.settings = self.load_settings()
        self.current_theme = self.settings.get("theme", "default")

        # Top-most bar with action buttons: VPN, MacChanger, Settings
        top_bar = QHBoxLayout()
        # Place the action buttons at the very left/top as requested
        self.vpn_btn = QPushButton("VPN")
        self.vpn_btn.setToolTip("Show VPN controls")
        self.mac_btn = QPushButton("MacChanger")
        self.mac_btn.setToolTip("Show MacChanger controls")
        self.settings_btn = QPushButton("Settings")
        self.settings_btn.setToolTip("Open settings (theme)")

        
        top_bar.addStretch()
        top_bar.addWidget(self.settings_btn)

        # Initialize global info labels shown above tabs
        self.datetime_label = QLabel()
        self.user_label = QLabel(f"Current User: {os.getenv('USER', 'godsyye')}")
        self.update_datetime_timer = QTimer(self)
        self.update_datetime_timer.timeout.connect(self.update_datetime)
        self.update_datetime_timer.start(1000)
        self.update_datetime()  # initial

        # Create tab widget: VPN tab and MacChanger tab
        self.tab_widget = QTabWidget()

        # --- VPN tab ---
        self.vpn_tab = QWidget()
        vpn_layout = QVBoxLayout()

        # IP labels (appear inside VPN tab)
        self.ip_label = QLabel("Public IP: fetching...")
        self.ip_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.ip_details_label = QLabel("IP details: fetching...")
        self.ip_details_label.setWordWrap(True)
        self.ip_details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # Timer to refresh IP info (every 60 seconds)
        self.ip_timer = QTimer(self)
        self.ip_timer.timeout.connect(self.fetch_ip_info)
        self.ip_timer.start(60 * 1000)
        self.fetch_ip_info()

        # VPN profiles UI (moved into VPN tab)
        self.profiles = self.load_profiles()
        self.profile_list = QListWidget()
        self.update_profile_list()

        self.connect_btn = QPushButton("Connect")
        self.disconnect_btn = QPushButton("Disconnect")
        self.add_btn = QPushButton("Add Profile")
        self.remove_btn = QPushButton("Remove Profile")

        # VPN-specific status label
        self.vpn_status_label = QLabel("")
        self.vpn_status_label.setWordWrap(True)

        vpn_layout.addWidget(self.ip_label)
        vpn_layout.addWidget(self.ip_details_label)
        vpn_layout.addWidget(QLabel("VPN Profiles:"))
        vpn_layout.addWidget(self.profile_list)
        vpn_layout.addWidget(self.vpn_status_label)

        vpn_btn_row = QHBoxLayout()
        vpn_btn_row.addWidget(self.connect_btn)
        vpn_btn_row.addWidget(self.disconnect_btn)
        vpn_layout.addLayout(vpn_btn_row)

        vpn_btn_row2 = QHBoxLayout()
        vpn_btn_row2.addWidget(self.add_btn)
        vpn_btn_row2.addWidget(self.remove_btn)
        vpn_layout.addLayout(vpn_btn_row2)

        self.vpn_tab.setLayout(vpn_layout)
        self.tab_widget.addTab(self.vpn_tab, "VPN")

        # --- MacChanger tab ---
        self.mac_tab = QWidget()
        mac_layout = QVBoxLayout()

        # Interface selection
        iface_row = QHBoxLayout()
        iface_row.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        iface_row.addWidget(self.iface_combo)
        mac_layout.addLayout(iface_row)

        # Populate interfaces
        self._populate_interfaces()

        # Current MAC labels
        self.mac_label = QLabel("MAC: fetching...")
        self.mac_details_label = QLabel("MAC details: fetching...")
        self.mac_details_label.setWordWrap(True)

        # MacChanger buttons
        mc_btn_row = QHBoxLayout()
        self.mc_random_btn = QPushButton("Randomize MAC")
        self.mc_set_btn = QPushButton("Set MAC...")
        self.mc_restore_btn = QPushButton("Restore Original")
        mc_btn_row.addWidget(self.mc_random_btn)
        mc_btn_row.addWidget(self.mc_set_btn)
        mc_btn_row.addWidget(self.mc_restore_btn)

        # MacChanger-specific status label
        self.mac_status_label = QLabel("")
        self.mac_status_label.setWordWrap(True)

        mac_layout.addWidget(self.mac_label)
        mac_layout.addWidget(self.mac_details_label)
        mac_layout.addLayout(mc_btn_row)
        mac_layout.addWidget(self.mac_status_label)

        self.mac_tab.setLayout(mac_layout)
        self.tab_widget.addTab(self.mac_tab, "MacChanger")

        # Main layout: top bar, datetime/user, tabs
        main_vbox = QVBoxLayout()
        main_vbox.addLayout(top_bar)

        info_hbox = QHBoxLayout()
        info_hbox.addWidget(self.datetime_label)
        info_hbox.addStretch()
        info_hbox.addWidget(self.user_label)
        main_vbox.addLayout(info_hbox)

        # separator line
        separator = QLabel()
        separator.setStyleSheet("background-color: #cccccc; min-height: 1px; max-height: 1px;")
        main_vbox.addWidget(separator)

        main_vbox.addWidget(self.tab_widget)

        self.central_widget.setLayout(main_vbox)

        # Connections
        self.connect_btn.clicked.connect(self.connect_vpn)
        self.disconnect_btn.clicked.connect(self.disconnect_vpn)
        self.add_btn.clicked.connect(self.add_profile)
        self.remove_btn.clicked.connect(self.remove_profile)
        self.settings_btn.clicked.connect(self.open_settings)

        # Top action buttons to switch tabs
        self.vpn_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(0))
        self.mac_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(1))

        # MacChanger connections
        self.iface_combo.currentIndexChanged.connect(self.fetch_mac_info)
        self.mc_random_btn.clicked.connect(self.randomize_mac)
        self.mc_set_btn.clicked.connect(self.set_mac_dialog)
        self.mc_restore_btn.clicked.connect(self.restore_mac)

        # Apply theme
        self.apply_theme(self.current_theme, save=False)

        # Initial fetch of mac info if interfaces exist
        QTimer.singleShot(200, self.fetch_mac_info)

    def update_datetime(self):
        current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.datetime_label.setText(f"Current Date and Time (UTC): {current_time}")

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump({
                    "theme": self.current_theme
                }, f, indent=2)
        except Exception:
            pass

    def apply_theme(self, theme_name, save=True):
        """
        Apply theme across the entire application (so dialogs and message boxes are themed).
        theme_name: "default", "dark_white", "dark_green"
        save: if True, persist settings to file
        """
        self.current_theme = theme_name

        # Theme base colors
        if theme_name == "dark_white":
            bg = "#1e1e1e"
            text_color = "#FFFFFF"
            list_bg = "#202020"
            button_bg = "#2A2A2A"
            dialog_bg = "#151515"
        elif theme_name == "dark_green":
            bg = "#0c1410"
            text_color = "#7CFC00"  # green text
            list_bg = "#0f150f"
            button_bg = "#122012"
            dialog_bg = "#071009"
        else:  # default
            bg = "#FFFFFF"
            text_color = "#000000"
            list_bg = "#FFFFFF"
            button_bg = "#F0F0F0"
            dialog_bg = "#FFFFFF"

        # Build a stylesheet that targets application-wide widgets including dialogs and message boxes.
        stylesheet = f"""
        /* Main background for central widget and dialogs */
        QWidget {{
            background-color: {bg};
            color: {text_color};
        }}
        QMainWindow {{
            background-color: {bg};
        }}
        QDialog {{
            background-color: {dialog_bg};
            color: {text_color};
        }}
        QMessageBox {{
            background-color: {dialog_bg};
            color: {text_color};
        }}
        QFileDialog {{
            background-color: {dialog_bg};
            color: {text_color};
        }}
        QLabel {{
            color: {text_color};
        }}
        QListWidget {{
            background-color: {list_bg};
            color: {text_color};
        }}
        QLineEdit, QTextEdit {{
            background-color: {list_bg};
            color: {text_color};
        }}
        QPushButton {{
            background-color: {button_bg};
            color: {text_color};
        }}
        QInputDialog {{
            background-color: {dialog_bg};
            color: {text_color};
        }}
        QTabWidget::pane {{
            background: {bg};
        }}
        QTabBar::tab {{
            background: {button_bg};
            color: {text_color};
            padding: 6px;
        }}
        """

        # Apply stylesheet to application if possible (this will style dialogs and message boxes too)
        try:
            app = QApplication.instance()
            if app:
                app.setStyleSheet(stylesheet)
            else:
                # Fallback: apply to main window/central widget
                self.setStyleSheet(stylesheet)
        except Exception:
            try:
                self.setStyleSheet(stylesheet)
            except Exception:
                pass

        if save:
            self.save_settings()

    def open_settings(self):
        dlg = SettingsDialog(self, current_theme=self.current_theme)
        dlg.exec_()

    # ---------------- IP fetching (remains for VPN tab) ----------------
    def fetch_ip_info(self):
        """
        Fetch public IP and some location/ISP details from a free API (ip-api.com).
        Uses urllib to avoid adding external dependencies.
        """
        url = "http://ip-api.com/json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LuffyVPN-Client"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.load(resp)
                if data.get("status") == "success":
                    ip = data.get("query", "N/A")
                    city = data.get("city", "")
                    region = data.get("regionName", "")
                    country = data.get("country", "")
                    isp = data.get("isp", "")
                    org = data.get("org", "")
                    timezone = data.get("timezone", "")
                    lat = data.get("lat")
                    lon = data.get("lon")

                    self.ip_label.setText(f"Public IP: {ip}")
                    details = []
                    location = ", ".join(p for p in (city, region, country) if p)
                    if location:
                        details.append(f"Location: {location}")
                    if lat is not None and lon is not None:
                        details.append(f"Coordinates: {lat}, {lon}")
                    if isp:
                        details.append(f"ISP: {isp}")
                    if org:
                        details.append(f"Org: {org}")
                    if timezone:
                        details.append(f"Timezone: {timezone}")
                    self.ip_details_label.setText("\n".join(details) if details else "IP details unavailable.")
                else:
                    self.ip_label.setText("Public IP: unavailable")
                    self.ip_details_label.setText("IP details unavailable.")
        except urllib.error.URLError:
            self.ip_label.setText("Public IP: network error")
            self.ip_details_label.setText("Could not fetch IP details (network error).")
        except Exception:
            self.ip_label.setText("Public IP: error")
            self.ip_details_label.setText("Could not fetch IP details (unexpected error).")

    # ---------------- VPN actions (mostly unchanged; now uses vpn_status_label) ----------------
    def connect_vpn(self):
        selected = self.profile_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Error", "Please select a VPN profile.")
            return

        name = selected.text()
        config = self.profiles[name]

        if not os.path.exists(config):
            QMessageBox.warning(self, "Error", "Config file not found.")
            return

        if self.vpn_process:
            QMessageBox.information(self, "VPN", "VPN is already running.")
            return

        # Show credentials dialog
        dialog = CredentialsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            sudo_password = dialog.sudo_password.text()
            vpn_username = dialog.vpn_username.text()
            vpn_password = dialog.vpn_password.text()

            # Create temporary auth file
            auth_file = "vpn_auth.tmp"
            try:
                with open(auth_file, "w") as f:
                    f.write(f"{vpn_username}\n{vpn_password}")

                # Start VPN connection
                # Keep stdout/stderr pipes so we can detect when connection completes
                self.vpn_process = subprocess.Popen(
                    ["sudo", "-S", "openvpn", "--config", config, "--auth-user-pass", auth_file],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                # Send sudo password
                try:
                    self.vpn_process.stdin.write(f"{sudo_password}\n")
                    self.vpn_process.stdin.flush()
                except Exception:
                    # If we can't write to stdin, let process run; we'll still attempt to read output
                    pass

                self.vpn_status_label.setText(f"Connecting to {name}...")

                # Start thread to read output and detect "Initialization Sequence Completed"
                self.output_thread = VPNOutputReader(self.vpn_process)
                self.output_thread.line_emitted.connect(self.on_vpn_output)
                self.output_thread.connected.connect(self.on_vpn_connected)
                self.output_thread.disconnected.connect(self.on_vpn_disconnected)
                self.output_thread.start()

                # Schedule removal of the auth file a few seconds later to give OpenVPN time to read it.
                QTimer.singleShot(5000, lambda: self._safe_remove_file(auth_file))

                QMessageBox.information(self, "VPN", f"Connecting to {name}...")

            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
                # cleanup if process was not started
                if self.vpn_process and self.vpn_process.poll() is None:
                    try:
                        self.vpn_process.terminate()
                    except Exception:
                        pass
                    self.vpn_process = None
                self._safe_remove_file(auth_file)

    def _safe_remove_file(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def on_vpn_output(self, line):
        # Update VPN status label with the latest line (shortened)
        short = (line[:200] + "...") if len(line) > 200 else line
        self.vpn_status_label.setText(short)

    def on_vpn_connected(self):
        # Called from the output reader thread via signal; safe to show GUI dialogs here.
        self.vpn_status_label.setText("VPN Connected")
        QMessageBox.information(self, "VPN", "VPN Connected")
        # Refresh IP after short delay so system routing has applied
        QTimer.singleShot(3000, self.fetch_ip_info)

    def on_vpn_disconnected(self):
        # Called when process exits/terminates
        self.vpn_status_label.setText("VPN Disconnected")
        # Refresh IP after short delay so routing updates
        QTimer.singleShot(1000, self.fetch_ip_info)
        QMessageBox.information(self, "VPN", "VPN Disconnected")

    def disconnect_vpn(self):
        if self.vpn_process:
            try:
                self.vpn_process.terminate()
            except Exception:
                try:
                    self.vpn_process.kill()
                except Exception:
                    pass

            # stop reader thread
            if self.output_thread:
                try:
                    self.output_thread.stop()
                except Exception:
                    pass
                self.output_thread = None

            # clear process reference
            self.vpn_process = None

            # Refresh IP info immediately (and again shortly after to allow routing changes)
            self.fetch_ip_info()
            QTimer.singleShot(1000, self.fetch_ip_info)

            QMessageBox.information(self, "VPN", "Disconnected.")
            self.vpn_status_label.setText("Disconnected")
        else:
            QMessageBox.information(self, "VPN", "No VPN connection running.")

    # ---------------- Profiles persistence ----------------
    def load_profiles(self):
        if os.path.exists(PROFILES_FILE):
            try:
                with open(PROFILES_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_profiles(self):
        try:
            with open(PROFILES_FILE, "w") as f:
                json.dump(self.profiles, f, indent=2)
        except Exception:
            pass

    def update_profile_list(self):
        self.profile_list.clear()
        for name in self.profiles:
            self.profile_list.addItem(name)

    def add_profile(self):
        name, ok = QInputDialog.getText(self, "Profile Name", "Enter a name for the VPN profile:")
        if ok and name:
            config_file, _ = QFileDialog.getOpenFileName(self, "Select OpenVPN Config", "", "OVPN Files (*.ovpn)")
            if config_file:
                self.profiles[name] = config_file
                self.save_profiles()
                self.update_profile_list()

    def remove_profile(self):
        selected = self.profile_list.currentItem()
        if selected:
            name = selected.text()
            if name in self.profiles:
                del self.profiles[name]
                self.save_profiles()
                self.update_profile_list()

    # ---------------- MacChanger support ----------------
    def _populate_interfaces(self):
        # List network interfaces from /sys/class/net (works on Linux)
        try:
            ifaces = sorted(os.listdir("/sys/class/net"))
        except Exception:
            ifaces = []
        # Filter out loopback by default but let user choose it if they want
        # Place 'lo' at end if present
        if "lo" in ifaces:
            ifaces = [i for i in ifaces if i != "lo"] + ["lo"]
        self.iface_combo.clear()
        for iface in ifaces:
            self.iface_combo.addItem(iface)

    def fetch_mac_info(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.mac_label.setText("MAC: N/A")
            self.mac_details_label.setText("MAC details unavailable.")
            return

        # Attempt to use macchanger -s <iface> to get details (if installed). Fallback to sysfs.
        try:
            p = subprocess.run(["macchanger", "-s", iface], capture_output=True, text=True, timeout=3)
            if p.returncode == 0 and p.stdout:
                # Show first lines of macchanger output
                lines = [line.strip() for line in p.stdout.splitlines() if line.strip()]
                # macchanger -s usually prints something like:
                # Current MAC:   00:11:22:33:44:55 (unknown)
                # Permanent MAC: ...
                # We display them raw for clarity
                self.mac_label.setText(lines[0] if lines else "MAC: unknown")
                self.mac_details_label.setText("\n".join(lines[1:]) if len(lines) > 1 else "No further details.")
                return
        except FileNotFoundError:
            # macchanger not installed; fall back to sysfs
            pass
        except Exception:
            pass

        # Fallback: read from /sys/class/net/<iface>/address and possibly permanent address
        try:
            addr_path = f"/sys/class/net/{iface}/address"
            with open(addr_path, "r") as f:
                mac = f.read().strip()
            # try to read permanent address (not always present)
            perm = None
            perm_path = f"/sys/class/net/{iface}/perm_address"
            if os.path.exists(perm_path):
                try:
                    with open(perm_path, "r") as f:
                        perm = f.read().strip()
                except Exception:
                    perm = None
            details = []
            if perm and perm != mac:
                details.append(f"Permanent MAC: {perm}")
            details.append(f"Current MAC: {mac}")
            # try to get operstate
            try:
                with open(f"/sys/class/net/{iface}/operstate", "r") as f:
                    state = f.read().strip()
                details.append(f"State: {state}")
            except Exception:
                pass
            self.mac_label.setText(f"MAC: {mac}")
            self.mac_details_label.setText("\n".join(details))
        except Exception:
            self.mac_label.setText("MAC: unavailable")
            self.mac_details_label.setText("Could not fetch MAC details.")

    def _run_with_sudo(self, cmd_list, sudo_password, timeout=10):
        """
        Helper to run a command prefixed with sudo -S and provide password via stdin.
        Returns (returncode, stdout+stderr)
        """
        try:
            proc = subprocess.Popen(["sudo", "-S"] + cmd_list,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    text=True,
                                    universal_newlines=True)
            # write password
            try:
                proc.stdin.write(sudo_password + "\n")
                proc.stdin.flush()
            except Exception:
                pass
            out, _ = proc.communicate(timeout=timeout)
            return proc.returncode, out
        except Exception as e:
            return 255, str(e)

    def randomize_mac(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Please select an interface.")
            return
        dlg = CredentialsDialog(self)
        # Only need sudo password; inform user that VPN username/password fields are optional
        dlg.setWindowTitle("MacChanger - Sudo Password")
        if dlg.exec_() == QDialog.Accepted:
            sudo_password = dlg.sudo_password.text()
            if not sudo_password:
                QMessageBox.warning(self, "Error", "System password required to change MAC.")
                return
            # Run macchanger -r iface via sudo
            if not shutil_which("macchanger"):
                QMessageBox.warning(self, "Error", "macchanger is not installed or not in PATH.")
                return
            self.mac_status_label.setText(f"Randomizing MAC on {iface}...")
            rc, out = self._run_with_sudo(["macchanger", "-r", iface], sudo_password, timeout=15)
            if rc == 0:
                self.mac_status_label.setText("MAC randomized successfully.")
            else:
                self.mac_status_label.setText(f"macchanger failed (code {rc}). See output.")
            # Update details (some time may be needed for kernel to reflect change)
            QTimer.singleShot(1000, self.fetch_mac_info)
            # Optionally show output to user
            QMessageBox.information(self, "MacChanger Output", out)

    def set_mac_dialog(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Please select an interface.")
            return
        mac, ok = QInputDialog.getText(self, "Set MAC Address", "Enter new MAC address (format: XX:XX:XX:XX:XX:XX):")
        if not ok or not mac:
            return
        dlg = CredentialsDialog(self)
        dlg.setWindowTitle("MacChanger - Sudo Password")
        if dlg.exec_() == QDialog.Accepted:
            sudo_password = dlg.sudo_password.text()
            if not sudo_password:
                QMessageBox.warning(self, "Error", "System password required to change MAC.")
                return
            if not shutil_which("macchanger"):
                QMessageBox.warning(self, "Error", "macchanger is not installed or not in PATH.")
                return
            self.mac_status_label.setText(f"Setting MAC on {iface} to {mac}...")
            rc, out = self._run_with_sudo(["macchanger", "-m", mac, iface], sudo_password, timeout=15)
            if rc == 0:
                self.mac_status_label.setText("MAC set successfully.")
            else:
                self.mac_status_label.setText(f"macchanger failed (code {rc}). See output.")
            QTimer.singleShot(1000, self.fetch_mac_info)
            QMessageBox.information(self, "MacChanger Output", out)

    def restore_mac(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Please select an interface.")
            return
        dlg = CredentialsDialog(self)
        dlg.setWindowTitle("MacChanger - Sudo Password")
        if dlg.exec_() == QDialog.Accepted:
            sudo_password = dlg.sudo_password.text()
            if not sudo_password:
                QMessageBox.warning(self, "Error", "System password required to restore MAC.")
                return
            if not shutil_which("macchanger"):
                QMessageBox.warning(self, "Error", "macchanger is not installed or not in PATH.")
                return
            self.mac_status_label.setText(f"Restoring original MAC on {iface}...")
            rc, out = self._run_with_sudo(["macchanger", "-p", iface], sudo_password, timeout=15)
            if rc == 0:
                self.mac_status_label.setText("MAC restored successfully.")
            else:
                self.mac_status_label.setText(f"macchanger failed (code {rc}). See output.")
            QTimer.singleShot(1000, self.fetch_mac_info)
            QMessageBox.information(self, "MacChanger Output", out)


# small helper because shutil.which isn't imported by default above
def shutil_which(cmd):
    # Minimal replacement for shutil.which to avoid importing shutil explicitly
    paths = os.environ.get("PATH", "").split(os.pathsep)
    exts = ['']
    if os.name == 'nt':
        pathext = os.environ.get("PATHEXT", "").split(os.pathsep)
        exts = pathext if pathext else exts
    for p in paths:
        full = os.path.join(p, cmd)
        for e in exts:
            candidate = full + e
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None
