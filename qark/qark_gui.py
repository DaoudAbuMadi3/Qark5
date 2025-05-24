from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout,
    QLineEdit, QCheckBox, QComboBox, QTextEdit, QMessageBox, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect  # Add transparency effect Add transparency effect
)
from PyQt5.QtCore import QTimer, Qt, QPropertyAnimation, QEasingCurve, QPoint
from PyQt5.QtGui import QFont, QColor, QPainter, QPixmap, QPalette, QLinearGradient
import subprocess
import sys
import os
import random
 

# Welcome window with effects
class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Welcome to QARK")
        self.setGeometry(400, 200, 600, 400)
        self.setStyleSheet("background-color: black;")
        
        # Background effect (Zoom In with Animation)
        self.bg_label = QLabel(self)
        self.bg_label.setGeometry(0, 0, 600, 400)
        
        # Animated Background Zoom-in Effect (works by resizing the widget)
        self.zoom_anim = QPropertyAnimation(self.bg_label, b"geometry")
        self.zoom_anim.setDuration(8000)
        self.zoom_anim.setStartValue(self.bg_label.geometry())
        self.zoom_anim.setEndValue(self.bg_label.geometry().adjusted(-30, -30, 30, 30))
        self.zoom_anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.zoom_anim.start()

        # Particle effect (simple glowing points)
        self.particles = []
        self.timer_particles = QTimer(self)
        self.timer_particles.timeout.connect(self.create_particle)
        self.timer_particles.start(100)  # Change to 100 ms to reduce the number of particles.

        # QARK Label with animation
        self.label = QLabel("", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setFont(QFont("Orbitron", 52, QFont.Bold))
        self.label.setStyleSheet("color: #00ffe0; background: transparent;")
        self.label.setGeometry(0, 150, 600, 100)
        self.label.raise_()

        # Glow effect for the label
        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(50)
        glow.setColor(QColor("#00ffe0"))
        glow.setOffset(0)
        self.label.setGraphicsEffect(glow)

        # Text animation
        self.full_text = "QARK-V5"
        self.current_index = 0
        self.displayed_text = ""
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.reveal_next_char)
        self.timer.start(500)

    def reveal_next_char(self):
        if self.current_index < len(self.full_text):
            self.displayed_text += self.full_text[self.current_index]
            self.label.setText(self.displayed_text)

            self.pulse_animation()
            self.current_index += 1
        else:
            self.timer.stop()
            QTimer.singleShot(2000, self.close_and_open_main)

    def pulse_animation(self):
        anim = QPropertyAnimation(self.label, b"geometry")
        anim.setDuration(300)
        anim.setStartValue(self.label.geometry().adjusted(-10, -5, 10, 5))
        anim.setEndValue(self.label.geometry())
        anim.setEasingCurve(QEasingCurve.OutBounce)
        anim.start()

    def create_particle(self):
        # Random position for the particle
        x = random.randint(0, 600)
        y = random.randint(0, 400)
        size = random.randint(3, 8)
        particle = Particle(self, QPoint(x, y), size)
        self.particles.append(particle)
        particle.show()

    def close_and_open_main(self):
        self.close()
        self.main_window = QARKGui()
        self.main_window.show()


class Particle(QLabel):
    def __init__(self, parent, position, size):
        super().__init__(parent)
        self.setGeometry(position.x(), position.y(), size, size)
        self.setStyleSheet("background-color: #00ffe0; border-radius: 50%;")
        
        # Add transparency effect
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        
        # Particle move animation
        self.move_animation = QPropertyAnimation(self, b"pos")
        self.move_animation.setDuration(random.randint(2000, 5000))
        self.move_animation.setStartValue(self.pos())
        self.move_animation.setEndValue(QPoint(random.randint(0, 600), random.randint(0, 400)))
        self.move_animation.setEasingCurve(QEasingCurve.OutBounce)
        self.move_animation.start()
        
        # Fade animation using QGraphics Opacity Effect
        self.fade_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_animation.setDuration(1500)
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.fade_animation.start()
        
        # Delete the particle after the effect ends
        self.fade_animation.finished.connect(self.deleteLater)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setBrush(QColor("#00ffe0"))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, self.width(), self.height())


class QARKGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QARK - Quick Android Review Kit")
        self.setGeometry(200, 200, 600, 400)

        # Set gradient background
        gradient = QLinearGradient(0, 0, 0, 400)
        gradient.setColorAt(0, QColor(0, 30, 60))  # Darker shade from above
        gradient.setColorAt(1, QColor(0, 180, 255))  # lighter shade at the bottom
        self.setAutoFillBackground(True)
        p = self.palette()
        p.setBrush(QPalette.Background, gradient)
        self.setPalette(p)

        # Element design
        self.layout = QVBoxLayout()

        self.apk_label = QLabel("APK / Java Path:")
        self.apk_label.setStyleSheet("color: #00ffe0; font-size: 18px; font-weight: bold;")
        self.apk_path_input = QLineEdit()
        self.apk_path_input.setStyleSheet("background-color: #2a2a2a; color: white; border-radius: 5px; padding: 10px;")
        self.browse_button = QPushButton("Browse")
        self.browse_button.setStyleSheet("background-color: #00ffe0; color: black; border-radius: 5px; padding: 10px; font-size: 14px;")
        self.browse_button.clicked.connect(self.browse_file)

        self.sdk_label = QLabel("SDK Path (optional):")
        self.sdk_label.setStyleSheet("color: #00ffe0; font-size: 18px; font-weight: bold;")
        self.sdk_input = QLineEdit()
        self.sdk_input.setStyleSheet("background-color: #2a2a2a; color: white; border-radius: 5px; padding: 10px;")

        self.report_type_label = QLabel("Report Type:")
        self.report_type_label.setStyleSheet("color: #00ffe0; font-size: 18px; font-weight: bold;")
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["html", "json", "xml", "csv"])
        self.report_type_combo.setStyleSheet("background-color: #2a2a2a; color: white; border-radius: 5px; padding: 10px;")

        self.exploit_checkbox = QCheckBox("Create Exploit APK")
        self.exploit_checkbox.setStyleSheet("color: #00ffe0; font-size: 16px;")
        self.debug_checkbox = QCheckBox("Enable Debug")
        self.debug_checkbox.setStyleSheet("color: #00ffe0; font-size: 16px;")

        self.run_button = QPushButton("Run QARK")
        self.run_button.setStyleSheet("background-color: #00ffe0; color: black; border-radius: 5px; padding: 15px; font-size: 16px;")
        self.run_button.clicked.connect(self.run_qark)

        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #2a2a2a; color: white; border-radius: 5px; padding: 10px; font-family: Consolas, monospace;")

        # Add elements to the interface
        for widget in [self.apk_label, self.apk_path_input, self.browse_button,
                       self.sdk_label, self.sdk_input,
                       self.report_type_label, self.report_type_combo,
                       self.exploit_checkbox, self.debug_checkbox,
                       self.run_button, self.output_console]:
            self.layout.addWidget(widget)

        self.setLayout(self.layout)

        # Add shadow effect to buttons
        self.add_shadow_effect(self.apk_label)
        self.add_shadow_effect(self.apk_path_input)
        self.add_shadow_effect(self.browse_button)
        self.add_shadow_effect(self.sdk_label)
        self.add_shadow_effect(self.sdk_input)
        self.add_shadow_effect(self.report_type_label)
        self.add_shadow_effect(self.report_type_combo)
        self.add_shadow_effect(self.exploit_checkbox)
        self.add_shadow_effect(self.debug_checkbox)
        self.add_shadow_effect(self.run_button)
        self.add_shadow_effect(self.output_console)

    def add_shadow_effect(self, widget):
        """Add shadow effect to UI elements"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 160))
        shadow.setOffset(0, 0)
        widget.setGraphicsEffect(shadow)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select APK or Java File")
        if file_path:
            self.apk_path_input.setText(file_path)

    def run_qark(self):
        apk_path = self.apk_path_input.text()
        sdk_path = self.sdk_input.text()
        report_type = self.report_type_combo.currentText()
        exploit = self.exploit_checkbox.isChecked()
        debug = self.debug_checkbox.isChecked()

        if not apk_path:
            QMessageBox.warning(self, "Missing Input", "Please select a source file.")
            return

        cmd = ["python3", "qark.py"]
        if apk_path.endswith(".apk"):
            cmd += ["--apk", apk_path]
        else:
            cmd += ["--java", apk_path]

        if sdk_path:
            cmd += ["--sdk-path", sdk_path]

        if exploit:
            cmd.append("--exploit-apk")
        if debug:
            cmd.append("--debug")

        cmd += ["--report-type", report_type]

        self.output_console.append("Running command:\n" + " ".join(cmd))
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        out, err = process.communicate()
        self.output_console.append("\n=== Output ===\n" + out)
        if err:
            self.output_console.append("\n=== Errors ===\n" + err)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    sys.exit(app.exec_())
