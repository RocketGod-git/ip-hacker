## ip-hacker

---

### **Overview**

ip-hacker is an advanced OSINT tool tailored for Discord, enabling cyber investigators, security researchers, and enthusiasts to gather in-depth data on target IP addresses. By integrating a broad spectrum of utilities into one platform, this bot provides real-time insights into an IP's geolocation, associated services, potential security threats, and more. Its foundation lies in its ability to seamlessly interact with the user, combining convenience and data-driven decision-making into one unified experience.

---

### **Table of Contents**

1. [Installation](#installation)
2. [Requirements](#requirements)
   - [Python Dependencies](#python-dependencies)
   - [External Dependencies](#external-dependencies)
3. [Configuration](#configuration)
4. [Usage & Features](#usage--features)
5. [Benefits of Team-Based OSINT](#benefits-of-team-based-osint)

---

### **Installation**

**Clone the Repository**:

```bash
git clone https://github.com/RocketGod-git/ip-hacker.git
cd ip-hacker
```

---

### **Requirements**

#### **Python Dependencies**

**Windows**:

```bash
pip install -r requirements.txt
```

**Linux**:

```bash
pip3 install -r requirements.txt
```

#### **External Dependencies**

1. **Nmap**:
   
   Nmap (Network Mapper) is an indispensable tool for port scanning. It determines what services an IP address is running, providing insights into potential vulnerabilities.

   **Installation**:

   **Debian/Ubuntu**:

   ```bash
   sudo apt-get install nmap
   ```

   **Windows**:

   - Download from [Nmap's official website](https://nmap.org/download.html) and install.

   **Make sure Nmap is in your PATH**:

   After installing, ensure Nmap is accessible from the command line by adding it to your system's PATH.

   Check out Nmap's [GitHub repository](https://github.com/nmap/nmap) for more details and potential contributions.

---

### **Configuration**

Update `config.json`:

```json
{
    "TOKEN": "YOUR DISCORD BOT TOKEN HERE",
    "SHODAN_KEY": "YOUR SHODAN API KEY HERE",
    "VIRUSTOTAL_API_KEY": "YOUR VIRUSTOTAL API KEY HERE"
}
```

**API Key Instructions**:

1. **Shodan**: 
   - Visit [Shodan's website](https://www.shodan.io/).
   - Create an account or log in.
   - Once logged in, navigate to 'My Account' on the top right.
   - Here, you'll find your API Key. Use this key for the "SHODAN_KEY" in the `config.json`.

2. **VirusTotal**: 
   - Visit [VirusTotal's website](https://www.virustotal.com/).
   - Register or sign in.
   - Navigate to the API section from the profile menu.
   - Here, you will find your public API Key. Use this key for the "VIRUSTOTAL_API_KEY" in the `config.json`.

---

### **Usage & Features**

**Running the Tool**:

**Windows**:

```bash
python main.py
```

**Linux**:

```bash
python3 main.py
```

#### **Features**:

1. **Clickable Links**: When the bot identifies open ports, it provides clickable links for quick access to the related services.
2. **Comprehensive Data Extraction**:
   - **Geolocation**: Determine an IP's geographical origin.
   - **Tor Exit Node Check**: Identify if an IP is a known TOR exit node.
   - **Whois Data**: Acquire domain or IP related metadata.
   - **Nmap Scans**: Port scans, mainly for ports 20-80, with additional scans for specific services like IP cameras, game servers, and others.
   - **Shodan & VirusTotal Integration**: Extract device details, vulnerabilities, and extensive security reports related to the IP.

---

### **Benefits of Team-Based OSINT**

Utilizing `ip-hacker` in a team setting on Discord offers:

1. **Real-time Sharing**: Share data instantly.
2. **Collaborative Analysis**: Multiple perspectives offer deeper insights.
3. **Unified Data**: Keep all gathered intel in one place.
4. **Efficient Task Distribution**: Assign specific investigation areas.
5. **Learning & Mentorship**: Real-time learning and guidance for members.

Integrate the strengths of collaborative OSINT operations with the data extraction capabilities of `ip-hacker` for an enhanced investigatory experience.

---

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

[LICENSE](LICENSE)


![rocketgod_logo](https://github.com/RocketGod-git/shodanbot/assets/57732082/7929b554-0fba-4c2b-b22d-6772d23c4a18)