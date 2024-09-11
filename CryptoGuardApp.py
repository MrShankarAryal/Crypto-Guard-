import os
import hashlib
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, 
                             QProgressBar, QDialog, QTextEdit, QFrame, QMenu, QAction)
from PyQt5.QtGui import QIcon, QFont, QPixmap, QPainter, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPoint
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class CryptoGuard:
    def __init__(self, user_file, user_key):
        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = hashlib.sha256(self.user_key).digest()
        self.file_extension = self.user_file.split(".")[-1]
        self.hash_type = "SHA256"
        self.encrypt_output_file = self.user_file + ".CryptoGuard"
        self.decrypt_output_file = self.user_file.replace(".CryptoGuard", "")
        self.hashed_key_salt = dict()
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def hash_key_salt(self):
        self.hashed_key_salt['key'] = hashlib.new(self.hash_type, self.user_key).digest()[:32]
        self.hashed_key_salt['salt'] = hashlib.new(self.hash_type, self.user_salt).digest()[:16]

    def generate_file_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in self.read_in_chunks(f):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def encrypt(self):
        encrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, self.hashed_key_salt['salt'])
        file_hash = self.generate_file_hash(self.user_file)
        with open(self.user_file, "rb") as f_input:
            with open(self.encrypt_output_file, "wb") as f_output:
                f_output.write(self.hashed_key_salt['salt'])
                f_output.write(file_hash.encode('utf-8'))
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    encrypted_chunk = encrypt_cipher.encrypt(chunk)
                    f_output.write(encrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)

    def verify_file_hash(self, file_path, original_hash):
        current_hash = self.generate_file_hash(file_path)
        return current_hash == original_hash

    def decrypt(self):
        with open(self.user_file, "rb") as f_input:
            salt = f_input.read(16)
            original_hash = f_input.read(64).decode('utf-8')
            decrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, salt)
            with open(self.decrypt_output_file, "wb") as f_output:
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    decrypted_chunk = decrypt_cipher.decrypt(chunk)
                    f_output.write(decrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)
        
        if not self.verify_file_hash(self.decrypt_output_file, original_hash):
            os.remove(self.decrypt_output_file)
            raise ValueError("Decryption failed: File integrity check failed.")

    def abort(self):
        if os.path.exists(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.exists(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

class CryptoThread(QThread):
    progress = pyqtSignal(float)
    finished = pyqtSignal(bool, str)

    def __init__(self, cipher, operation):
        super().__init__()
        self.cipher = cipher
        self.operation = operation

    def run(self):
        try:
            for percentage in (self.cipher.encrypt() if self.operation == "encrypt" else self.cipher.decrypt()):
                self.progress.emit(percentage)
            self.finished.emit(True, f"File {self.operation.capitalize()}ed successfully!")
        except Exception as e:
            self.finished.emit(False, str(e))

class CustomTitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(10, 0, 10, 0)
        self.setFixedHeight(40)  # Set fixed height for title bar

        # Logo and title
        logo_label = QLabel()
        logo_pixmap = QPixmap("assets/icon.ico").scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        self.layout.addWidget(logo_label)
        title_label = QLabel("CryptoGuard")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
        self.layout.addWidget(title_label)
        self.layout.addSpacing(20)

        # Spacer
        self.layout.addStretch()

        # Help and About buttons
        self.help_button = QPushButton("Help")
        self.about_button = QPushButton("About")
        for button in (self.help_button, self.about_button):
            button.setFixedSize(60, 30)
            button.setStyleSheet("""
                QPushButton {
                    border: none;
                    color: #FFFFFF;
                    background-color: transparent;
                }
                QPushButton:hover {
                    background-color: rgba(255, 255, 255, 30);
                }
            """)
        self.layout.addWidget(self.help_button)
        self.layout.addWidget(self.about_button)

        # Window controls
        self.minimize_button = QPushButton("—")
        self.close_button = QPushButton("✕")
        for button in (self.minimize_button, self.close_button):
            button.setFixedSize(40, 30)
            button.setStyleSheet("""
                QPushButton {
                    border: none;
                    color: #FFFFFF;
                    background-color: transparent;
                }
                QPushButton:hover {
                    background-color: rgba(255, 255, 255, 30);
                }
            """)
        self.close_button.setStyleSheet("""
            QPushButton {
                border: none;
                color: #FFFFFF;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: #E81123;
            }
        """)
        self.layout.addWidget(self.minimize_button)
        self.layout.addWidget(self.close_button)

        # Connect buttons
        self.minimize_button.clicked.connect(self.parent.showMinimized)
        self.close_button.clicked.connect(self.parent.close)
        self.help_button.clicked.connect(self.parent.show_help)
        self.about_button.clicked.connect(self.parent.show_about)

        self.start = QPoint(0, 0)
        self.pressing = False

    def resizeEvent(self, QResizeEvent):
        super().resizeEvent(QResizeEvent)
        self.setFixedWidth(self.parent.width())

    def mousePressEvent(self, event):
        self.start = self.mapToGlobal(event.pos())
        self.pressing = True

    def mouseMoveEvent(self, event):
        if self.pressing:
            end = self.mapToGlobal(event.pos())
            movement = end - self.start
            self.parent.setGeometry(self.parent.x() + movement.x(), self.parent.y() + movement.y(),
                                    self.parent.width(), self.parent.height())
            self.start = end

    def mouseReleaseEvent(self, QMouseEvent):
        self.pressing = False

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(0, 120, 212))  # Windows 10 blue color
        painter.drawRect(self.rect())


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoGuard")
        self.setGeometry(100, 100, 500, 350)
        self.setWindowFlags(Qt.FramelessWindowHint)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Custom title bar
        self.title_bar = CustomTitleBar(self)
        self.main_layout.addWidget(self.title_bar)

        # Content widget
        self.content_widget = QWidget()
        self.content_widget.setObjectName("contentWidget")
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.addWidget(self.content_widget)

        # Theme menu
        self.theme_menu = QMenu(self)
        self.theme_menu.addAction("Light Theme", lambda: self.set_theme("light"))
        self.theme_menu.addAction("Dark Theme", lambda: self.set_theme("dark"))
        self.theme_menu.addAction("System Theme", lambda: self.set_theme("system"))

        self.theme_button = QPushButton("Theme")
        self.theme_button.setFixedSize(60, 30)
        self.theme_button.setStyleSheet("""
            QPushButton {
                border: none;
                color: #FFFFFF;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 30);
            }
        """)
        self.theme_button.clicked.connect(self.show_theme_menu)
        self.title_bar.layout.insertWidget(self.title_bar.layout.count() - 2, self.theme_button)

        self.setup_ui()
        self.set_theme("system")  # Set default theme


    def setup_ui(self):
       # File selection
        file_layout = QHBoxLayout()
        self.file_label = QLabel("File:")
        self.file_input = QLineEdit()
        self.file_button = QPushButton("Select")
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(self.file_button)
        self.content_layout.addLayout(file_layout)

        # Secret key
        key_layout = QHBoxLayout()
        self.key_label = QLabel("Secret Key:")
        self.key_input = QLineEdit()
        self.generate_button = QPushButton("Generate")
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(self.generate_button)
        self.content_layout.addLayout(key_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.reset_button = QPushButton("Reset")
        self.cancel_button = QPushButton("Cancel")
        action_layout.addWidget(self.encrypt_button)
        action_layout.addWidget(self.decrypt_button)
        action_layout.addWidget(self.reset_button)
        action_layout.addWidget(self.cancel_button)
        self.content_layout.addLayout(action_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.content_layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Status: Ready")
        self.content_layout.addWidget(self.status_label)

        # Connect signals
        self.file_button.clicked.connect(self.select_file)
        self.generate_button.clicked.connect(self.generate_secret_key)
        self.encrypt_button.clicked.connect(lambda: self.process_file("encrypt"))
        self.decrypt_button.clicked.connect(lambda: self.process_file("decrypt"))
        self.reset_button.clicked.connect(self.reset)
        self.cancel_button.clicked.connect(self.cancel)

    def set_theme(self, theme):
        if theme == "light":
            self.setStyleSheet("""
                QMainWindow, QWidget#contentWidget {
                    background-color: #F0F0F0;
                    border: 1px solid #CCCCCC;
                }
                QLabel {
                    color: #333333;
                }
                QPushButton {
                    background-color: #0078D7;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #1E90FF;
                }
                QLineEdit {
                    padding: 5px;
                    border: 1px solid #CCCCCC;
                    border-radius: 3px;
                    background-color: white;
                    color: #333333;
                }
                QProgressBar {
                    border: 1px solid #CCCCCC;
                    border-radius: 3px;
                    background-color: #E0E0E0;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #0078D7;
                    width: 10px;
                    margin: 0.5px;
                }
                QMessageBox, QDialog {
                    background-color: #F0F0F0;
                }
                QMessageBox QLabel, QDialog QLabel {
                    color: #333333;
                }
                QMessageBox QPushButton, QDialog QPushButton {
                    background-color: #0078D7;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QMessageBox QPushButton:hover, QDialog QPushButton:hover {
                    background-color: #1E90FF;
                }
                QTextEdit {
                    background-color: white;
                    color: #333333;
                    border: 1px solid #CCCCCC;
                }
                QHeaderView::section {
                    background-color: #0078D7;
                    color: white;
                    padding: 5px;
                    border: 1px solid #CCCCCC;
                }
            """)
        elif theme == "dark":
            self.setStyleSheet("""
                QMainWindow, QWidget#contentWidget {
                    background-color: #2D2D2D;
                    border: 1px solid #555555;
                }
                QLabel {
                    color: #FFFFFF;
                }
                QPushButton {
                    background-color: #0078D7;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #1E90FF;
                }
                QLineEdit {
                    padding: 5px;
                    border: 1px solid #555555;
                    border-radius: 3px;
                    background-color: #3D3D3D;
                    color: #FFFFFF;
                }
                QProgressBar {
                    border: 1px solid #555555;
                    border-radius: 3px;
                    background-color: #3D3D3D;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #0078D7;
                    width: 10px;
                    margin: 0.5px;
                }
                QMessageBox, QDialog {
                    background-color: #2D2D2D;
                }
                QMessageBox QLabel, QDialog QLabel {
                    color: #FFFFFF;
                }
                QMessageBox QPushButton, QDialog QPushButton {
                    background-color: #0078D7;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QMessageBox QPushButton:hover, QDialog QPushButton:hover {
                    background-color: #1E90FF;
                }
                QTextEdit {
                    background-color: #3D3D3D;
                    color: #FFFFFF;
                    border: 1px solid #555555;
                }
                QHeaderView::section {
                    background-color: #0078D7;
                    color: white;
                    padding: 5px;
                    border: 1px solid #555555;
                }
            """)
        else:  # System theme
            self.setStyleSheet("""
                QMainWindow, QWidget#contentWidget {
                    background-color: palette(window);
                    border: 1px solid palette(mid);
                }
                QLabel {
                    color: palette(text);
                }
                QPushButton {
                    background-color: palette(button);
                    color: palette(button-text);
                    border: 1px solid palette(mid);
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: palette(light);
                }
                QLineEdit {
                    padding: 5px;
                    border: 1px solid palette(mid);
                    border-radius: 3px;
                    background-color: palette(base);
                    color: palette(text);
                }
                QProgressBar {
                    border: 1px solid palette(mid);
                    border-radius: 3px;
                    background-color: palette(base);
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: palette(highlight);
                    width: 10px;
                    margin: 0.5px;
                }
                QMessageBox, QDialog {
                    background-color: palette(window);
                }
                QMessageBox QLabel, QDialog QLabel {
                    color: palette(text);
                }
                QMessageBox QPushButton, QDialog QPushButton {
                    background-color: palette(button);
                    color: palette(button-text);
                    border: 1px solid palette(mid);
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QMessageBox QPushButton:hover, QDialog QPushButton:hover {
                    background-color: palette(light);
                }
                QTextEdit {
                    background-color: palette(base);
                    color: palette(text);
                    border: 1px solid palette(mid);
                }
                QHeaderView::section {
                    background-color: palette(button);
                    color: palette(button-text);
                    padding: 5px;
                    border: 1px solid palette(mid);
                }
            """)
        
        # Update title bar color
        title_bar_color = "#2D2D2D" if theme == "dark" else ("#0078D7" if theme == "light" else "palette(window)")
        self.title_bar.setStyleSheet(f"""
            CustomTitleBar {{
                background-color: {title_bar_color};
            }}
        """)

    def show_theme_menu(self):
        self.theme_menu.exec_(self.theme_button.mapToGlobal(QPoint(0, self.theme_button.height())))

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_input.setText(file_path)

    def generate_secret_key(self):
        key_bytes = get_random_bytes(32)
        key_str = key_bytes.hex()
        self.key_input.setText(key_str)

    def process_file(self, operation):
        if not self.file_input.text():
            self.show_error("Error", "Please select a file.")
            return
        if not self.key_input.text():
            self.show_error("Error", "Secret key cannot be blank.")
            return

        self.cipher = CryptoGuard(self.file_input.text(), self.key_input.text())
        self.thread = CryptoThread(self.cipher, operation)
        self.thread.progress.connect(self.update_progress)
        self.thread.finished.connect(self.process_finished)
        self.thread.start()

        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self.status_label.setText(f"Status: {operation.capitalize()}ing...")

    def update_progress(self, value):
        self.progress_bar.setValue(int(value))

    def process_finished(self, success, message):
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Status: {message}")
        if not success:
            self.show_error("Error", message)

    def reset(self):
        self.file_input.clear()
        self.key_input.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Ready")

    def cancel(self):
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.terminate()
            self.cipher.abort()
            self.status_label.setText("Status: Cancelled")
            self.encrypt_button.setEnabled(True)
            self.decrypt_button.setEnabled(True)
            self.progress_bar.setValue(0)

    def show_error(self, title, message):
        QMessageBox.critical(self, title, message)

    def show_about(self):
        about_text = "CryptoGuard\nVersion 1.2.0\nDeveloped by Shankar Aryal"
        QMessageBox.about(self, "About", about_text)

    def show_help(self):
            help_text = """1. Click 'Select' to choose a file for encryption/decryption.
    2. Enter a Secret Key or click 'Generate' for a random key.
    3. Click 'Encrypt' to encrypt the file or 'Decrypt' for decryption.
    4. The progress bar will show the operation's progress.
    5. Click 'Reset' to clear all fields.
    6. Click 'Cancel' to stop an ongoing operation."""
            
            help_dialog = QDialog(self)
            help_dialog.setWindowTitle("Help")
            help_dialog.setMinimumSize(400, 300)
            
            layout = QVBoxLayout(help_dialog)
            text_edit = QTextEdit()
            text_edit.setPlainText(help_text)
            text_edit.setReadOnly(True)
            layout.addWidget(text_edit)
            
            close_button = QPushButton("Close")
            close_button.clicked.connect(help_dialog.close)
            layout.addWidget(close_button)
            
            help_dialog.setStyleSheet(self.styleSheet())
            help_dialog.exec_()

    def show_about(self):
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle("About CryptoGuard")
        about_dialog.setFixedSize(400, 350)
        about_layout = QVBoxLayout(about_dialog)

        # Horizontal layout for logo and app name
        header_layout = QHBoxLayout()

        # Add logo image (make sure you have a logo image, e.g., 'cryptoguard_logo.png' in your project directory)
        logo_label = QLabel()
        pixmap = QPixmap("assets/icon.png").scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        
        # App name and version in h2 style
        app_name_label = QLabel("<h2>CryptoGuard</h2>")

        # Add logo and app name side by side
        header_layout.addWidget(logo_label)
        header_layout.addWidget(app_name_label)
        header_layout.addStretch()  # Pushes the items to the left for a clean look

        # Add the header layout to the main layout
        about_layout.addLayout(header_layout)

        # About description
        about_label = QLabel("""
            <p>Version: 1.1.4</p>
            <p>Developed by: <b>Shankar Aryal</b></p>
            <p>
            CryptoGuard is a robust file encryption and decryption application, providing secure and easy-to-use functionality using AES-GCM encryption. Whether you are protecting sensitive documents or securing personal files, CryptoGuard ensures data integrity and confidentiality.
            </p>
            <p>
            Documentation, source code, and more details can be found on our GitHub repository:
            </p>
            <a href='https://github.com/MrShankarAryal/Crypto-Guard-'>https://github.com/MrShankarAryal/Crypto-Guard-</a>
        """)
        about_label.setWordWrap(True)
        about_label.setOpenExternalLinks(True)
        about_layout.addWidget(about_label)

        # Close button
        close_button = QPushButton("Close")
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #0078D7;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #1E90FF;
            }
        """)
        close_button.clicked.connect(about_dialog.close)
        about_layout.addWidget(close_button)
        about_layout.setAlignment(close_button, Qt.AlignCenter)

        about_dialog.exec_()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
