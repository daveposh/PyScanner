#!/usr/bin/env python3
"""
Network Ping Sweeper
A GUI application for network scanning using ICMP ping.

Author: Dave
GitHub: https://github.com/dave
Created: December 2024
License: MIT
"""

import sys
import ipaddress
import threading
import socket
from ping3 import ping
from typing import Optional
import netifaces
import dns.resolver
import dns.reversename
import platform
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QCheckBox, QTreeWidget, QTreeWidgetItem, QMessageBox,
                            QFrame, QComboBox, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

__author__ = "Dave"
__version__ = "1.0.0"
__license__ = "MIT"
__email__ = "dave@example.com"

def get_macos_dns_servers():
    try:
        output = subprocess.check_output(['scutil', '--dns'], text=True)
        dns_servers = []
        for line in output.split('\n'):
            if 'nameserver[' in line:
                server = line.split()[2]
                if server not in dns_servers:
                    dns_servers.append(server)
        return dns_servers
    except Exception as e:
        print(f"Error getting macOS DNS servers: {e}")
        return []

def get_network_info():
    networks = []
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            gateway_iface = gateways['default'][netifaces.AF_INET][1]
            
            addrs = netifaces.ifaddresses(gateway_iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        ip = addr['addr']
                        netmask = addr['netmask']
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.append({
                            'network': str(network),
                            'gateway': default_gateway,
                            'interface': gateway_iface
                        })
    except Exception as e:
        print(f"Error getting network info: {e}")
    return networks

class ScanWorker(QThread):
    result_ready = pyqtSignal(str, str, str, str)
    finished = pyqtSignal()
    
    def __init__(self, ip_list, timeout,Dav size, resolve_hostnames):
        super().__init__()
        self.ip_list = ip_list
        self.timeout = timeout
        self.size = size
        self.resolve_hostnames = resolve_hostnames
        self.running = True
        
        # Initialize DNS resolver with system DNS servers
        self.resolver = dns.resolver.Resolver()
        
        # Get DNS servers based on OS
        if platform.system() == 'Darwin':  # macOS
            dns_servers = get_macos_dns_servers()
        else:  # Linux/Unix systems
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    dns_servers = []
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            except Exception:
                dns_servers = []
        
        # Use system DNS servers or fall back to Google DNS
        if dns_servers:
            self.resolver.nameservers = dns_servers
        else:
            self.resolver.nameservers = ['8.8.8.8']
        
        print(f"Using DNS servers: {self.resolver.nameservers}")
        
    def get_hostname(self, ip: str) -> str:
        if not self.resolve_hostnames:
            return "N/A"
            
        print(f"Attempting to resolve hostname for {ip}")
        
        try:
            # Method 1: Direct socket resolution
            try:
                print(f"Trying direct socket resolution for {ip}")
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"Socket resolution successful: {hostname}")
                return hostname
            except Exception as e:
                print(f"Socket resolution failed: {e}")
            
            # Method 2: DNS PTR lookup
            try:
                print(f"Trying DNS PTR lookup for {ip}")
                addr = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(addr, "PTR")
                if answers:
                    hostname = str(answers[0]).rstrip('.')
                    print(f"PTR lookup successful: {hostname}")
                    return hostname
            except Exception as e:
                print(f"PTR lookup failed: {e}")
            
        except Exception as e:
            print(f"All hostname resolution methods failed for {ip}: {e}")
        
        return "N/A"
    
    def ping_host(self, ip: str) -> Optional[float]:
        try:
            result = ping(str(ip), timeout=self.timeout, size=self.size)
            print(f"Ping result for {ip}: {result}")
            return result
        except Exception as e:
            print(f"Ping failed for {ip}: {e}")
            return None
    
    def run(self):
        for ip in self.ip_list:
            if not self.running:
                break
                
            response_time = self.ping_host(str(ip))
            hostname = self.get_hostname(str(ip)) if response_time is not None else "N/A"
            
            status = "Active" if response_time is not None else "Inactive"
            time_str = f"{response_time:.2f} ms" if response_time is not None else "N/A"
            
            self.result_ready.emit(str(ip), status, time_str, hostname)
            
        self.finished.emit()
    
    def stop(self):
        self.running = False

class PingSweeper(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Ping Sweeper")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Network selection section
        network_frame = QFrame()
        network_frame.setFrameStyle(QFrame.StyledPanel)
        network_layout = QHBoxLayout(network_frame)
        network_layout.addWidget(QLabel("Network:"))
        
        self.network_combo = QComboBox()
        self.network_combo.currentIndexChanged.connect(self.on_network_changed)
        network_layout.addWidget(self.network_combo)
        layout.addWidget(network_frame)
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.StyledPanel)
        input_layout = QHBoxLayout(input_frame)
        input_layout.addWidget(QLabel("IP/Range/CIDR:"))
        self.ip_input = QLineEdit()
        input_layout.addWidget(self.ip_input)
        layout.addWidget(input_frame)
        
        # Settings section
        settings_frame = QFrame()
        settings_frame.setFrameStyle(QFrame.StyledPanel)
        settings_layout = QHBoxLayout(settings_frame)
        
        settings_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_input = QLineEdit("1")
        self.timeout_input.setFixedWidth(60)
        settings_layout.addWidget(self.timeout_input)
        
        settings_layout.addWidget(QLabel("Packet Size:"))
        self.size_input = QLineEdit("56")
        self.size_input.setFixedWidth(60)
        settings_layout.addWidget(self.size_input)
        
        self.resolve_checkbox = QCheckBox("Resolve Hostnames")
        self.resolve_checkbox.setChecked(True)
        settings_layout.addWidget(self.resolve_checkbox)
        
        settings_layout.addStretch()
        layout.addWidget(settings_frame)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        # Left side buttons (scan control)
        scan_buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_scan)
        scan_buttons_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        scan_buttons_layout.addWidget(self.stop_button)
        
        button_layout.addLayout(scan_buttons_layout)
        button_layout.addStretch()
        
        # Right side buttons (results management)
        results_buttons_layout = QHBoxLayout()
        
        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(self.clear_results)
        results_buttons_layout.addWidget(self.clear_button)
        
        self.clear_inactive_button = QPushButton("Clear Inactive")
        self.clear_inactive_button.clicked.connect(self.clear_inactive_results)
        results_buttons_layout.addWidget(self.clear_inactive_button)
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        results_buttons_layout.addWidget(self.export_button)
        
        button_layout.addLayout(results_buttons_layout)
        layout.addLayout(button_layout)
        
        # Results tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["IP Address", "Status", "Response Time", "Hostname"])
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree)
        
        # Populate networks
        self.networks = get_network_info()
        for net in self.networks:
            self.network_combo.addItem(f"{net['network']} (Gateway: {net['gateway']})", net)
        
        if self.networks:
            self.ip_input.setText(self.networks[0]['network'])
        
        self.scan_worker = None
        
    def on_network_changed(self, index):
        if index >= 0 and index < len(self.networks):
            self.ip_input.setText(self.networks[index]['network'])
    
    def validate_input(self):
        input_text = self.ip_input.text().strip()
        
        if '/' in input_text:
            try:
                network = ipaddress.ip_network(input_text, strict=False)
                return True, list(network.hosts())
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid CIDR notation")
                return False, []
        
        if '-' in input_text:
            try:
                start_ip, end_ip = input_text.split('-')
                start_ip = ipaddress.ip_address(start_ip.strip())
                end_ip = ipaddress.ip_address(end_ip.strip())
                
                if start_ip > end_ip:
                    QMessageBox.critical(self, "Error", "Invalid IP range: start IP is greater than end IP")
                    return False, []
                
                ip_list = []
                current_ip = start_ip
                while current_ip <= end_ip:
                    ip_list.append(current_ip)
                    current_ip += 1
                return True, ip_list
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid IP range format")
                return False, []
        
        try:
            ip = ipaddress.ip_address(input_text)
            return True, [ip]
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")
            return False, []
    
    def add_result(self, ip, status, time, hostname):
        item = QTreeWidgetItem([ip, status, time, hostname])
        self.tree.addTopLevelItem(item)
        self.tree.scrollToBottom()
    
    def start_scan(self):
        if not self.ip_input.text().strip():
            QMessageBox.critical(self, "Error", "Please enter an IP address, range, or CIDR block")
            return
        
        try:
            timeout = float(self.timeout_input.text())
            size = int(self.size_input.text())
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid timeout or packet size value")
            return
        
        valid, ip_list = self.validate_input()
        if not valid:
            return
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        self.scan_worker = ScanWorker(
            ip_list,
            timeout,
            size,
            self.resolve_checkbox.isChecked()
        )
        self.scan_worker.result_ready.connect(self.add_result)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
    
    def scan_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def clear_results(self):
        self.tree.clear()
    
    def clear_inactive_results(self):
        """Remove all inactive hosts from the results."""
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount() - 1, -1, -1):
            item = root.child(i)
            if item.text(1) == "Inactive":  # Status column
                root.removeChild(item)
    
    def export_results(self):
        """Export scan results to a text file."""
        if self.tree.topLevelItemCount() == 0:
            QMessageBox.warning(self, "Export", "No results to export!")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    # Write header
                    f.write("Network Scan Results\n")
                    f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"{'IP Address':<20} {'Status':<10} {'Response Time':<15} {'Hostname'}\n")
                    f.write("-" * 80 + "\n")
                    
                    # Write results
                    root = self.tree.invisibleRootItem()
                    for i in range(root.childCount()):
                        item = root.child(i)
                        f.write(f"{item.text(0):<20} {item.text(1):<10} {item.text(2):<15} {item.text(3)}\n")
                    
                    f.write("-" * 80 + "\n")
                    f.write(f"Total hosts scanned: {root.childCount()}\n")
                    
                QMessageBox.information(self, "Export", "Results exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = PingSweeper()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
