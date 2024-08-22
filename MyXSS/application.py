import glob
import os
import re
import sys
from threading import Thread

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QTableWidget,
                             QTableWidgetItem, QFileDialog, QGridLayout, QHeaderView, QHBoxLayout)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from lib.crawler import *
from lib.log import *
from lib.scanner import *


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


payloads_dir = resource_path('payloads')
payloads_files = glob.glob(os.path.join(payloads_dir, '*'))


class Application(QWidget):
    scan_finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle('MyXSS Scanner')
        self.setGeometry(100, 100, 800, 700)
        self.setStyleSheet("background-color: #f5f5f5;")
        self.create_initial_widgets()
        self.scan_finished.connect(self.generate_report)

    def clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            widget = child.widget()
            if widget:
                widget.deleteLater()
            else:
                self.clear_layout(child.layout())

    def create_initial_widgets(self):
        Log.clear_log()
        scanner.detected_vulnerabilities.clear()

        layout = self.layout()
        if layout is not None:
            self.clear_layout(layout)
        else:
            layout = QVBoxLayout()

        # Add logo/image
        image_label = QLabel(self)
        image_path = resource_path('images/xss.jpeg')
        pixmap = QPixmap(image_path).scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        image_label.setPixmap(pixmap)
        image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(image_label)

        # URL Entry
        self.url_label = QLabel("Enter URL to Scan:")
        self.url_label.setFont(QFont("Arial", 16))
        layout.addWidget(self.url_label)

        self.url_entry = QLineEdit(self)
        self.url_entry.setPlaceholderText("https://example.com")
        self.url_entry.setStyleSheet("background-color: #ffffff; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.url_entry)

        # Scan buttons
        self.fast_scan_button = QPushButton("Fast Scan")
        self.fast_scan_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 15px; border-radius: 5px; font-size: 16px;")
        self.fast_scan_button.clicked.connect(self.fast_scan)
        layout.addWidget(self.fast_scan_button)

        self.normal_scan_button = QPushButton("Normal Scan")
        self.normal_scan_button.setStyleSheet("background-color: #2196F3; color: white; padding: 15px; border-radius: 5px; font-size: 16px;")
        self.normal_scan_button.clicked.connect(self.normal_scan)
        layout.addWidget(self.normal_scan_button)

        layout.setAlignment(Qt.AlignTop)
        self.setLayout(layout)

    def fast_scan(self):
        url = self.url_entry.text()
        if url:
            Thread(target=self.start_scan, args=(url, True)).start()

    def normal_scan(self):
        url = self.url_entry.text()
        if url:
            Thread(target=self.start_scan, args=(url, False)).start()

    def start_scan(self, url, is_fast_scan):
        layout = self.layout()
        if layout is not None:
            self.clear_layout(layout)
        else:
            layout = QVBoxLayout()

        if is_fast_scan:
            scanner.main(url, payloads_files, callback=self.on_crawl_finished)
        else:
            scanner.main(url, payloads_files)
            crawler.crawl(url, payloads_files, callback=self.on_crawl_finished)

    def on_crawl_finished(self):
        self.scan_finished.emit()

    def generate_report(self):
        layout = self.layout()
        self.clear_layout(layout)

        # Scanning report title
        title_label = QLabel("Scanning Report")
        title_label.setFont(QFont("Arial", 24))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # Vulnerability status
        status_text_label = QLabel("Website XSS Vulnerability Status:")
        status_text_label.setFont(QFont("Arial", 14))
        status_text_label.setStyleSheet("color: black")
        layout.addWidget(status_text_label)

        status_label = QLabel("Vulnerable" if scanner.detected_vulnerabilities else "Safe")
        status_label.setFont(QFont("Arial", 14))
        status_label.setStyleSheet("color: red" if scanner.detected_vulnerabilities else "color: green")
        layout.addWidget(status_label)

        # Threat assessment
        if scanner.detected_vulnerabilities:
            self.show_threat_assessment(layout)

        # Detailed table of vulnerabilities
        if scanner.detected_vulnerabilities:
            self.show_vulnerabilities_table(layout)
        else:
            no_vulnerabilities_label = QLabel("No vulnerabilities found!")
            no_vulnerabilities_label.setFont(QFont('Arial', 16))
            no_vulnerabilities_label.setStyleSheet("color: green")
            no_vulnerabilities_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(no_vulnerabilities_label)

        # Buttons for exporting report and scanning again
        self.show_action_buttons(layout)

    def show_threat_assessment(self, layout):
        status_label = QLabel("\nThreat assessment for the detected payload types:\n")
        status_label.setFont(QFont("Arial", 14))
        status_label.setStyleSheet("color: darkred; font-weight: bold;")
        layout.addWidget(status_label)

        payloads_dict = {os.path.splitext(os.path.basename(f))[0]: f for f in payloads_files}
        vuln_percentage = {}

        for vulnerability in scanner.detected_vulnerabilities:
            type_of_vulnerability = vulnerability['Payload file']
            payload_used = vulnerability['Payload']
            payload_file = payloads_dict.get(type_of_vulnerability)

            if payload_file:
                with open(payload_file, 'r') as f:
                    payloads = [line.strip() for line in f.readlines()]
                try:
                    payload_position = payloads.index(payload_used)
                    percentage = 100 * (len(payloads) - payload_position) / len(payloads)
                    vuln_percentage[(type_of_vulnerability, payload_used)] = percentage
                except ValueError:
                    print(f"Payload used: '{payload_used}' not found in payloads for vulnerability type: {type_of_vulnerability}")

        pie_chart_layout = QGridLayout()
        row, col = 0, 0

        for record, percentage in vuln_percentage.items():
            fig, ax = plt.subplots(figsize=(2, 2))
            wedges, _ = ax.pie([percentage, 100 - percentage], colors=['red', 'green'], startangle=90)

            for wedge in wedges:
                wedge.set_edgecolor('white')

            ax.set_title(f"{record[0]}", y=0.85)
            canvas = FigureCanvas(fig)
            pie_chart_layout.addWidget(canvas, row, col)

            col += 1
            if col > 3:
                col = 0
                row += 1

        layout.addLayout(pie_chart_layout)

    def show_vulnerabilities_table(self, layout):
        status_label = QLabel("\nDetailed table of found vulnerabilities:\n")
        status_label.setFont(QFont("Arial", 14))
        status_label.setStyleSheet("color: darkred; font-weight: bold;")
        layout.addWidget(status_label)

        self.table = QTableWidget()
        layout.addWidget(self.table)

        data = [[v['Payload file'], v['HTTP Method'], v['URL'], v['Payload']] for v in scanner.detected_vulnerabilities]

        self.table.setRowCount(len(data))
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Type of Vulnerability", "Method", "URL", "Payload Used"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        for i, row_data in enumerate(data):
            for j, column_data in enumerate(row_data):
                self.table.setItem(i, j, QTableWidgetItem(str(column_data)))

            link_label = QLabel(f'<a href="http://example.com">Learn more...</a>')
            link_label.setOpenExternalLinks(True)
            self.table.setCellWidget(i, 4, link_label)

    def show_action_buttons(self, layout):
        button_width = int(self.width() * 0.4)

        self.export_button = QPushButton("Save Report")
        self.export_button.setStyleSheet("background-color: #FFC107; padding: 15px; border-radius: 5px;")
        self.export_button.setFixedWidth(button_width)
        self.export_button.clicked.connect(self.export_report)

        self.scan_again_button = QPushButton("Scan Again")
        self.scan_again_button.setStyleSheet("background-color: #03A9F4; padding: 15px; border-radius: 5px;")
        self.scan_again_button.setFixedWidth(button_width)
        self.scan_again_button.clicked.connect(self.create_initial_widgets)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.scan_again_button)
        button_layout.setAlignment(Qt.AlignCenter)

        layout.addLayout(button_layout)

    def export_report(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt)")

        if file_name:
            with open(file_name, 'w') as file:
                file.write("_______________________________________ MyXSS scanning report _______________________________________\n")
                for log in Log.log_dict["VULNERABILITY"]:
                    file.write(log + "\n")


def main():
    app = QApplication(sys.argv)
    ex = Application()
    ex.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
