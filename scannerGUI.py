#!/usr/bin/python3

import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLineEdit, QLabel, QTextEdit, QStatusBar, QRadioButton
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot

from scanner import host_list, port_list, scan_host

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'IT567 Port Scanner'
        self.left = 10
        self.top = 10
        self.width = 400
        self.height = 400
        self.initUI()
 
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self.host_label = QLabel("IPs:", self)
        self.host_label.move(20, 14)
 
        self.host_text = QLineEdit(self)
        self.host_text.move(80, 20)
        self.host_text.resize(140,20)
        self.host_text.returnPressed.connect(self.on_click)

        self.port_label = QLabel("Ports:", self)
        self.port_label.move(20, 44)

        self.port_text = QLineEdit(self)
        self.port_text.move(80, 50)
        self.port_text.resize(140, 20)
        self.port_text.returnPressed.connect(self.on_click)

        self.tcp_button = QRadioButton("TCP", self)
        self.tcp_button.move(20, 80)
        self.tcp_button.setChecked(True)

        self.udp_button = QRadioButton("UDP", self)
        self.udp_button.move(80, 80)
 
        # Create a button in the window
        self.button = QPushButton('Scan', self)
        self.button.move(20, 120)
        self.button.setAutoDefault(True)

        self.output = QTextEdit(self)
        self.output.setReadOnly(True)
        self.output.move(20, 160)
        self.output.resize(360, 210)
 
        # connect button to function on_click
        self.button.clicked.connect(self.on_click)
        self.show()
 
    @pyqtSlot()
    def on_click(self):
        if not self.host_text.text():
            self.statusBar.showMessage("No hosts specified")
            return

        if not self.port_text.text():
            self.statusBar.showMessage("No ports specified")
            return

        try:
            hosts = host_list(self.host_text.text())
            ports = port_list(self.port_text.text())
        except ValueError as e:
            self.statusBar.showMessage(str(e))
            return

        self.output.setText("")
        for host in hosts:
            udp = self.udp_button.isChecked()
            protocol = "UDP" if udp else "TCP"
            self.output.append("Host {} ({}):".format(host, protocol))
            for port in scan_host(host, ports, udp=udp):
                self.output.append(str(port))

        self.output.append("Done")

if __name__ == '__main__':
	app = QApplication(sys.argv)
	ex = App()
	sys.exit(app.exec_())
