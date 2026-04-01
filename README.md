# DNS Spoofing and Detection System

## 📌 Overview
This project demonstrates a **DNS Spoofing Attack** and a **Detection Mechanism** using Python and Scapy.  
The aim is to show how attackers can manipulate DNS responses to redirect victims to malicious IPs, and how defenders can detect and prevent such activities.

> ⚠ **Educational Purpose Only**  
> This project is intended solely for cybersecurity research and education in a controlled lab environment.

---

## 🚀 Features
- **DNS Spoofing Module** → Redirects DNS queries for a target domain to a fake IP.
- **Detection Module** → Monitors network traffic for suspicious DNS responses.
- **Customizable** → Modify target domain and spoof IP easily.
- **Logging** → Saves detection logs for analysis.
- **Cross-Platform** → Works on Linux & Windows (with admin/root privileges).

---

## 🛠 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/AnshumanRajSingh/dns-spoofing-project.git
cd dns-spoofing-project
```

### 2️⃣ Install Requirements
```bash
pip install -r requirements.txt
```

### 3️⃣ Run with Root/Admin Privileges  
On **Linux/Kali**:
```bash
sudo python3 dns_spoof.py
```
On **Windows (PowerShell)**:
```powershell
python dns_spoof.py
```

---

## 📜 Usage

### **Run DNS Spoofing**
```bash
sudo python3 dns_spoof.py -t <target_domain> -i <fake_ip>
```
Example:
```bash
sudo python3 dns_spoof.py -t example.com -i 192.168.1.100
```

### **Run DNS Detection**
```bash
sudo python3 dns_detect.py
```
This will monitor traffic and alert if it detects spoofed DNS responses.

---

## 📂 Project Structure
```
dns-spoofing-project/
│-- dns_spoof.py       # Spoofing script
│-- dns_detect.py      # Detection script
│-- requirements.txt   # Dependencies
│-- README.md          # Documentation
```

---

## 🖥 Example Output

**Spoofing Script:**
```
[+] Sending spoofed DNS reply to 192.168.1.5 for example.com -> 192.168.1.100
```

**Detection Script:**
```
[ALERT] Possible DNS spoofing detected:
Domain: example.com
Expected IP: 93.184.216.34
Received IP: 192.168.1.100
```
---

## ⚠ Disclaimer
This project is for **educational purposes only**.  
Do **NOT** run this on networks you don’t own or have explicit permission to test.  
Misuse of this code can result in legal consequences.

---

## 📜 License
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
