# dns-spoofing-project
 Overview
This project demonstrates both the attack and defense aspects of DNS spoofing. It uses Python and Scapy to intercept DNS requests and respond with forged IP addr>

⚠️ Disclaimer: This project is for educational and cybersecurity research purposes only. Do not use it on networks without explicit permission.

🛠 Features
DNS Spoofing Module – Redirects DNS requests to a malicious IP.

Detection Module – Monitors DNS traffic for anomalies.

Customizable Target Domains – Configure which domains to spoof.

Logging – Saves suspicious activity details for analysis.

📂 Project Structure
graphql
Copy
Edit
📁 dns-spoofing-detection/
 ├── spoof.py          # DNS spoofing script
 ├── detect.py         # DNS spoof detection script
 ├── README.md         # Project documentation
 └── requirements.txt  # Python dependencies
🔧 Installation
1️⃣ Clone the Repository
bash
Copy
Edit
git clone https://github.com/YOUR-USERNAME/dns-spoofing-detection.git
cd dns-spoofing-detection
 Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
🚀 Usage
Start DNS Spoofing
bash
Copy
Edit
sudo python3 spoof.py
Run Detection Module
bash
Copy
Edit
sudo python3 detect.py
📊 Example Output (Detection Module)
yaml
Copy
Edit
[ALERT] Possible DNS spoofing detected!
Domain: example.com
Expected IP: 93.184.216.34
Received IP: 192.168.1.100
⚠ Legal Notice
This project is inte
📚 References
RFC 1035 – Domain Names Implementation

Scapy Documentation

OWASP DNS Security Guide

nded for authorized penetration testing and network security training only.

Unauthorized use may be illegal and result in severe penalties.

The author is not responsible for any misuse.
