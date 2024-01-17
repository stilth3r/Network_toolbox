import sys
import json
import subprocess
import psutil
import socket
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit,
    QPushButton, QWidget, QComboBox,
    QListWidget, QListWidgetItem, QGridLayout, QMessageBox, QFrame
)
from PyQt5.QtGui import QPalette, QColor, QIcon
from PyQt5.QtCore import Qt, QTimer, QThread
from ping3 import ping
import re
import os
import qdarktheme

class ApplyProfileThread(QThread):
    def __init__(self, interface, ip_address, subnet_mask, gateway, dns_server):
        super(ApplyProfileThread, self).__init__()
        self.interface = interface
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.dns_server = dns_server

    def run(self):
        command_address = [
            "netsh", "interface", "ipv4", "set", "address",
            "name={}".format(self.interface), "static", self.ip_address, self.subnet_mask, self.gateway
        ]
        subprocess.run(command_address, shell=False)

        command_dns = [
            "netsh", "interface", "ipv4", "set", "dns",
            "name={}".format(self.interface), "static", self.dns_server
        ]
        subprocess.run(command_dns, shell=False)

class NetworkConfigurator(QMainWindow):
    def __init__(self):
        super().__init__()

        self.apply_thread = None

        self.init_ui() 
        self.ping_timer = QTimer(self)
        self.ping_timer.timeout.connect(self.update_ping_status)
        self.ping_timer.start(1000)  

        icon_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'logo.png')
        self.setWindowIcon(QIcon(icon_path))

    def init_ui(self):
        self.setWindowTitle('Network Configurator')
        self.setGeometry(100, 100, 800, 500)

        


        # Left Side - Network Configuration
        self.interface_label = QLabel('Interface:')
        self.interface_combobox = QComboBox()
        self.update_interface_combobox()

        self.ip_label = QLabel('IP Address:')
        self.ip_input = QLineEdit()

        self.mask_label = QLabel('Subnet Mask:')
        self.mask_input = QLineEdit()

        self.gateway_label = QLabel('Gateway:')
        self.gateway_input = QLineEdit()

        self.left_label = QLabel('NETWORK CONFIGURATION')
        self.left_label.setObjectName('left_label')
        self.left_label.setAlignment(Qt.AlignCenter)

        self.right_label = QLabel('AUTOMATIC PING')
        self.right_label.setObjectName('right_label')
        self.right_label.setAlignment(Qt.AlignCenter)

        self.dns_label = QLabel('DNS Server:')
        self.dns_input = QLineEdit()

        self.save_button = QPushButton('Save Profile')
        self.save_button.clicked.connect(self.save_profile)

        self.remove_profile_button = QPushButton('Remove Profile')
        self.remove_profile_button.clicked.connect(self.remove_profile)

        self.apply_button = QPushButton('Apply Profile')
        self.apply_button.clicked.connect(self.apply_profile)

        self.dhcp_button = QPushButton('Set DHCP')
        self.dhcp_button.clicked.connect(self.set_dhcp)

        self.removeIP_button = QPushButton('Remove IP')
        self.removeIP_button.clicked.connect(self.remove_ip)

        # Right Side - IP List and Ping Status
        self.profile_list_label = QLabel('Profiles:')
        self.profile_list_widget = QListWidget()
        self.profile_list_widget.itemClicked.connect(self.load_profile_data)
        self.profile_list_widget.itemDoubleClicked.connect(self.load_and_apply)
        self.load_profiles()

        self.ip_list_label = QLabel('IP List:')
        self.ip_list_widget = QListWidget()
        self.load_ip_list()  # Appeler ici pour charger la liste d'IP

        self.ip_input_label = QLabel('IP:')
        self.add_ip_input = QLineEdit()
        self.ip_description_label = QLabel('Description:')
        self.ip_description_input = QLineEdit()

        self.add_ip_button = QPushButton('Add IP')
        self.add_ip_button.clicked.connect(self.add_ip_to_list)

        self.current_ipv4_label = QLabel('Current IPv4:')
        self.current_ipv4_value = QLabel('')
        self.current_ipv4_value.setAlignment(Qt.AlignLeft)

        self.ipv4_timer = QTimer(self)
        self.ipv4_timer.timeout.connect(self.update_current_ipv4)
        self.ipv4_timer.start(1000)

        separator_line = QFrame()
        separator_line.setFrameShape(QFrame.VLine)
        separator_line.setFrameShadow(QFrame.Sunken)

        layout_main = QGridLayout()
        layout_main.addWidget(self.left_label, 0, 1)
        layout_main.addWidget(self.interface_label, 1, 0)
        layout_main.addWidget(self.interface_combobox, 1, 1)
        layout_main.addWidget(self.ip_label, 3, 0)
        layout_main.addWidget(self.ip_input, 3, 1)  
        layout_main.addWidget(self.mask_label, 4, 0)
        layout_main.addWidget(self.mask_input, 4, 1)  
        layout_main.addWidget(self.gateway_label, 5, 0)
        layout_main.addWidget(self.gateway_input, 5, 1)  
        layout_main.addWidget(self.dns_label, 6, 0)
        layout_main.addWidget(self.dns_input, 6, 1)  
        layout_main.addWidget(self.save_button, 7, 1)
        layout_main.addWidget(self.remove_profile_button, 8, 1)
        layout_main.addWidget(self.apply_button, 9, 1)
        layout_main.addWidget(self.dhcp_button, 10, 1)
        layout_main.addWidget(self.profile_list_label, 11, 1)
        layout_main.addWidget(self.profile_list_widget, 12, 1, 20, 1)
        layout_main.addWidget(separator_line, 0, 2, 30, 1)
        layout_main.addWidget(self.right_label, 0, 4)
        layout_main.addWidget(self.ip_list_label, 1, 3)  
        layout_main.addWidget(self.ip_list_widget, 1, 4, 8, 1)  
        layout_main.addWidget(self.ip_description_label, 9, 3)  
        layout_main.addWidget(self.ip_description_input, 9, 4)  
        layout_main.addWidget(self.ip_input_label, 10, 3)  
        layout_main.addWidget(self.add_ip_input, 10, 4)  
        layout_main.addWidget(self.add_ip_button, 11, 4)  
        layout_main.addWidget(self.removeIP_button, 12,4)
        layout_main.addWidget(self.current_ipv4_label, 21, 3)
        layout_main.addWidget(self.current_ipv4_value, 21, 4)

        central_widget = QWidget()
        central_widget.setLayout(layout_main)
        self.setCentralWidget(central_widget)

    def update_interface_combobox(self):
        interfaces = self.get_network_interfaces()
        self.interface_combobox.clear()
        self.interface_combobox.addItems(interfaces)

        for index, interface in enumerate(interfaces):
            if interface.startswith("Ethernet"):
                self.interface_combobox.setCurrentIndex(index)
                break

    def get_network_interfaces(self):
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            if socket.AF_INET in {addr.family for addr in addrs}:
                interfaces.append(interface)
        return interfaces
    
    def load_and_apply(self, item):
        self.load_profile_data(item)
        self.apply_profile()

    def save_profile(self):
        # Implement profile saving logic here
        interface = self.interface_combobox.currentText()
        ip_address = self.ip_input.text()
        subnet_mask = self.mask_input.text()
        gateway = self.gateway_input.text()
        dns_server = self.dns_input.text()

        if not self.is_valid_ip(ip_address):
            self.show_error_message("Invalid IP Address format.")
            return

        if not self.is_valid_ip(subnet_mask):
            self.show_error_message("Invalid Subnet Mask format.")
            return


        profile_data = {
            'interface': interface,
            'ip_address': ip_address,
            'subnet_mask': subnet_mask,
            'gateway': gateway,
            'dns_server': dns_server
        }

        with open('profiles.json', 'a') as f:
            json.dump(profile_data, f)
            f.write('\n')

        self.load_profiles()

    def apply_profile(self):
        if self.apply_thread is not None and self.apply_thread.isRunning():
            self.show_error_message("Profile application already in progress.")
            return

        interface = self.interface_combobox.currentText()
        ip_address = self.ip_input.text()
        subnet_mask = self.mask_input.text()
        gateway = self.gateway_input.text()
        dns_server = self.dns_input.text()

        if not self.is_valid_ip(ip_address):
            self.show_error_message("Invalid IP Address format.")
            return

        if not self.is_valid_ip(subnet_mask):
            self.show_error_message("Invalid Subnet Mask format.")
            return

        # Create an instance of the ApplyProfileThread
        self.apply_thread = ApplyProfileThread(interface, ip_address, subnet_mask, gateway, dns_server)
        self.apply_thread.start()

    def closeEvent(self, event):
        # Override closeEvent to wait for the thread to finish before closing the application
        if self.apply_thread is not None and self.apply_thread.isRunning():
            self.show_error_message("Wait for the profile application to finish.")
            event.ignore()
        else:
            event.accept()


    def set_dhcp(self):
        # Implement DHCP configuration logic using subprocess here
        interface = self.interface_combobox.currentText()

        # Configurer l'adresse IP en mode DHCP
        command_address = f"netsh interface ipv4 set address name={interface} source=dhcp"
        subprocess.run(command_address, shell=True)

        # Réinitialiser les paramètres DNS en mode DHCP
        command_dns = f"netsh interface ipv4 set dns name={interface} source=dhcp"
        subprocess.run(command_dns, shell=True)

    def load_profiles(self):
        # Implement profile loading logic here
        self.profile_list_widget.clear()

        try:
            with open('profiles.json', 'r') as f:
                for line in f:
                    profile_data = json.loads(line)
                    profile_name = f"{profile_data['interface']} - {profile_data['ip_address']}"
                    item = QListWidgetItem(profile_name)
                    item.setData(1, profile_data)
                    self.profile_list_widget.addItem(item)
        except FileNotFoundError:
            pass

    def load_profile_data(self, item):
        profile_data = item.data(1)
        self.interface_combobox.setCurrentText(profile_data['interface'])
        self.ip_input.setText(profile_data['ip_address'])
        self.mask_input.setText(profile_data['subnet_mask'])
        self.gateway_input.setText(profile_data['gateway'])
        self.dns_input.setText(profile_data['dns_server'])

    # Ajouter cette fonction dans la classe NetworkConfigurator
    def remove_profile(self):
        selected_items = self.profile_list_widget.selectedItems()
        if not selected_items:
            return  # Aucun élément sélectionné

        # Supprimer le fichier profiles.json
        with open('profiles.json', 'r') as f:
            lines = f.readlines()

        with open('profiles.json', 'w') as f:
            for line in lines:
                profile_data = json.loads(line)
                profile_name = f"{profile_data['interface']} - {profile_data['ip_address']}"
                if profile_name not in [item.text() for item in selected_items]:
                    f.write(json.dumps(profile_data) + '\n')

        # Recharger la liste des profils
        self.load_profiles()

    def add_ip_to_list(self):
        new_ip = self.add_ip_input.text()
        description = self.ip_description_input.text()
        self.add_ip_input.clear()
        self.ip_description_input.clear()

        if not self.is_valid_ip(new_ip):
            self.show_error_message("Invalid IP Address format.")
            return

        if new_ip:
            ip_item = f"{description} - {new_ip}"
            self.ip_list_widget.addItem(ip_item)
            self.save_ip_list()  # Sauvegarder la liste des IP dans le fichier JSON
            self.ping_ip(new_ip)  # Ping l'IP ajoutée

    def remove_ip(self):
        selected_items = self.ip_list_widget.selectedItems()
        if not selected_items:
            return  # Aucun élément sélectionné

        # Charger la liste actuelle des IP
        ip_list = []
        for i in range(self.ip_list_widget.count()):
            ip_item = self.ip_list_widget.item(i)
            ip_data = ip_item.text().split(' - ')
            if len(ip_data) == 2:
                description, ip_address = ip_data
                ip_list.append({'description': description, 'ip_address': ip_address})

        # Supprimer l'IP sélectionnée
        for selected_item in selected_items:
            selected_ip_data = selected_item.text().split(' - ')
            if len(selected_ip_data) == 2:
                description, ip_address = selected_ip_data
                ip_list = [ip for ip in ip_list if ip['ip_address'] != ip_address]

        # Sauvegarder la liste mise à jour
        with open('ip_list.json', 'w') as f:
            json.dump(ip_list, f)

        # Recharger la liste des IP
        self.load_ip_list()
    
    # Ajouter ces fonctions dans la classe NetworkConfigurator
    def save_ip_list(self):
        ip_list = []
        for i in range(self.ip_list_widget.count()):
            ip_item = self.ip_list_widget.item(i)
            ip_data = ip_item.text().split(' - ')
            if len(ip_data) == 2:
                description, ip_address = ip_data
                ip_list.append({'description': description, 'ip_address': ip_address})

        with open('ip_list.json', 'w') as f:
            json.dump(ip_list, f)

    def load_ip_list(self):
        self.ip_list_widget.clear()
        try:
            with open('ip_list.json', 'r') as f:
                ip_list = json.load(f)
                for ip_data in ip_list:
                    ip_item = f"{ip_data['description']} - {ip_data['ip_address']}"
                    self.ip_list_widget.addItem(ip_item)
        except FileNotFoundError:
            pass

    # Modifier cette fonction dans la classe NetworkConfigurator
    def update_ping_status(self):
        for i in range(self.ip_list_widget.count()):
            ip_item = self.ip_list_widget.item(i)
            ip_address = ip_item.text().split(' - ')[1]  # Extraire l'adresse IP

            # Vérifiez le ping
            if self.ping_ip(ip_address):
                self.set_text_color(ip_item, Qt.green)
            else:
                self.set_text_color(ip_item, QColor(255, 100, 0))

    def ping_ip(self, ip_address):
        try:
            response = ping(ip_address, timeout=0.15)
            return response is not None
        except Exception as e:
            #print(f"Error pinging {ip_address}: {e}")
            return False

    def set_text_color(self, item, color):
        palette = QPalette()
        palette.setColor(QPalette.Text, color)
        item.setForeground(palette.color(QPalette.Text))

    def load_profile_data(self, item):
        profile_data = item.data(1)
        self.interface_combobox.setCurrentText(profile_data['interface'])
        self.ip_input.setText(profile_data['ip_address'])
        self.mask_input.setText(profile_data['subnet_mask'])
        self.gateway_input.setText(profile_data['gateway'])
        self.dns_input.setText(profile_data['dns_server'])

    def is_valid_ip(self, ip_address):
        ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
                                r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
                                r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
                                r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$")
        return bool(ip_pattern.match(ip_address))


    def show_error_message(self, message):
        error_message = QMessageBox(self)
        error_message.setStyleSheet("""
            QMessageBox {
                background-color: #444;
                color: #eee;  /* Ajoutez cela pour définir la couleur du texte */
            }

            QMessageBox QPushButton[text="OK"] {
                min-width: 100px;
                min-height: 30px;
            }
        """)
        error_message.setIcon(QMessageBox.Warning)
        error_message.setWindowTitle("Error")
        error_message.setText(message)
        error_message.exec_()
    
    def update_current_ipv4(self):
        # Mettre à jour l'IPv4 actuelle en fonction de l'interface sélectionnée
        interface = self.interface_combobox.currentText()
        current_ipv4 = self.get_current_ipv4(interface)
        self.current_ipv4_value.setText(current_ipv4)
    
    def get_current_ipv4(self, interface):
        # Obtenez l'adresse IPv4 actuelle de l'interface en utilisant psutil
        addrs = psutil.net_if_addrs().get(interface, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return 'N/A'


if __name__ == '__main__':
    app = QApplication(sys.argv)
        
    qdarktheme.setup_theme()
    main_win = QMainWindow()

    window = NetworkConfigurator()
    window.show()
    sys.exit(app.exec_())
