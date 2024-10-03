<img src="assets/icon.ico" alt="CryptoGuard Logo" width="100"/>

# Crypto-Guard

Crypto Guard: File Encryption and Decryption
CryptoGuard is a robust file encryption GUI application designed to provide secure, user-friendly encryption and decryption of files using AES in GCM mode.


# CryptoGuard:Used

## 📚 Libraries Used

- **os**: For file operations
- **hashlib**: For hashing
- **PyQt5**: For the GUI
- **Cryptodome**: For encryption and decryption (AES)

## 🏗️ Main Classes

- **CryptoGuard**: Handles the encryption and decryption logic
- **MainWindow**: Creates and manages the GUI

## 🔐 Encryption/Decryption Process

- Uses AES encryption in GCM mode
- Derives a salt from the user's key
- Reads and processes files in chunks for efficiency

## 🖥️ GUI Features

- File selection
- Secret key input
- Encrypt and Decrypt buttons
- Reset and Cancel buttons
- Status display
- Help and About menu items

## 🌟 Additional Features

- Progress tracking during encryption/decryption
- Ability to cancel ongoing operations
- Error handling and user feedback


## **📩 INSTALLATION Setup for New device:**

### Step 1: Create a virtual environment

```bash
python -m venv CryptoGuardapp_env
```

### Step 2: Activate the virtual environment
```bash
.\CryptoGuardapp_env\Scripts\activate
```

### Step 3: Install the required packages inside the virtual environment
```bash
pip install pycryptodomex
```
```bash
pip install cx_freeze
```

### Step 4: Install pyQt5
```bash
pip install pyQt5
```
```bash
python.exe -m pip install --upgrade pip
```
#customtkinter: https://customtkinter.tomschimansky.com/documentation/

### Step 4: Run your script
```bash
& "C:/Program Files/Python312/python.exe" "c:/Users/Shankar Aryal/Desktop/CryptoGuard/CryptoGuardApp.py"
```

## 🤝 Contributing

We welcome contributions to CryptoGuard! Your input is invaluable in making this project better.

### How to Contribute

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

We stand on the shoulders of giants. Special thanks to:

- [Cryptodome](https://www.pycryptodome.org/) - For providing robust cryptographic functions
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter) - For enhanced UI elements

## 📬 Contact

<div align="center">

| Contact | Information |
|---------|-------------|
| **Developer** | Shankar Aryal |
| **Email** | [shankararyal737@gmail.com](mailto:shankararyal737@gmail.com) |
| **GitHub** | [@MrShankarAryal](https://github.com/MrShankarAryal) |
| **Website** | [mrshankararyal.github.io](https://mrshankararyal.github.io/portfolio/) |

</div>

---

<div align="center">

💖 Thank you for your interest in CryptoGuard! 💖

</div>
