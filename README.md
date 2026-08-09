# CaDE - Cyber Analysis of Domains & Environment

CaDE is a lightweight web Application written in Python using Flask that performs basic domain reconnaissance, security checks, and technical stack fingerprinting.

## Features
- **WHOIS Lookup**: Fetch domain registration and server details.
- **Port Scanner**: Check open/closed status for common network ports.
- **Subdomain Finder**: Discover subdomains using wordlist enumeration.
- **HTTP Security Headers Check**: Analyze security-related HTTP headers.
- **Vulnerability Path Check**: Check common public endpoint paths.
- **Tech Stack Fingerprinting**: Detect server info and meta generators.

## Setup & Running Locally

### Prerequisites
- Python 3.8+ installed on your system.

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/CaDE.git
   cd CaDE
   ```

2. **Create and activate a virtual environment:**
   - **On Windows:**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - **On Linux/macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

5. **Open in browser:**
   Navigate to `http://127.0.0.1:5000` in your web browser.
