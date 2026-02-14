# Python for Hacking - Network Scanner & Attack Tool

> **⚠️ WARNING**: This tool is for **EDUCATIONAL PURPOSES ONLY**. Do not use it on networks or systems you do not own or have permission to test. The author is not responsible for any misuse.

## 🚀 Overview
A powerful, web-based network scanning and security testing dashboard built with **Flask** and **Python**. It provides a modern "hacker-style" interface for discovering devices, detecting operating systems, and performing targeted brute-force attacks.

## ✨ Features
-   **Network Scanner**: Discover active hosts on your local network.
-   **Advanced Scanning**: Run TCP, UDP, SYN, and Aggressive scans using Nmap.
-   **OS Detection**: Identify the operating system of target devices.
-   **Brute Force Tool**:
    -   Target SSH and Telnet services.
    -   **Scan before Attack**: Identify open ports before launching an attack.
    -   **Flexible Targeting**: Manually specify protocols and non-standard ports.
    -   **File Upload**: Upload custom password lists for attacks.
-   **Modern UI**: Glassmorphism design with neon accents and responsive layout.

## 🛠️ Prerequisites
Before running the tool, ensure you have the following installed:

1.  **Python 3.x**: [Download Python](https://www.python.org/downloads/)
    -   Ensure you verify installation by running `python --version` in your terminal.
2.  **Nmap**: This tool relies on Nmap for scanning.
    -   **Windows**: [Download Nmap](https://nmap.org/download.html). **IMPORTANT**: Ensure you check "Add Nmap to PATH" during installation.
    -   **Linux**: `sudo apt install nmap`
    -   **macOS**: `brew install nmap`

## 📦 Installation & Setup

It is recommended to use a virtual environment to manage dependencies.

### 1. Clone the Repository
Clone or download the source code and navigate to the `Backend` directory:
```bash
cd Backend
```

### 2. Create and Activate Virtual Environment

**Windows:**
```bash
# Create the environment
python -m venv venv

# Activate the environment
venv\Scripts\activate
```

**macOS / Linux:**
```bash
# Create the environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate
```

*(You will know it's activated when you see `(venv)` at the start of your command prompt.)*

### 3. Install Dependencies
With the environment activated, install the required libraries:
```bash
pip install -r requirements.txt
```

## 🚀 Usage

1.  Start the Flask application:
    ```bash
    python app.py
    ```
2.  Open your web browser and go to:
    ```
    http://127.0.0.1:5050
    ```
3.  **To use the Brute Force tool**:
    -   Go to the "Brute Force" tab.
    -   Select a target from the list or enter a custom IP.
    -   Click "Scan Target for Open Ports" to check for SSH/Telnet.
    -   Select a discovered port or manually enter Protocol/Port.
    -   Upload a password list or enter passwords manually.
    -   Click "Start Attack".

## 📂 Project Structure
-   `app.py`: Main Flask application.
-   `scanner_nmap.py`: Nmap scanning logic.
-   `attack_modules.py`: SSH and Telnet brute force logic.
-   `templates/`: HTML templates (modular components).
-   `static/`: CSS and JavaScript files.
-   `requirements.txt`: Python dependencies.

---
*Created for educational purposes.*