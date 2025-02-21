<div align="center">
  <img src="assets/msh-logo.png" alt="MSH CLI Logo" width="200"/>
  <h1>🛡️ MSH CLI</h1>
  <p><em>Advanced AI-Powered Security Testing & Analysis Framework</em></p>

  [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
  [![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu-blue)](https://www.kali.org/)
  [![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2016.0.0-brightgreen)](https://nodejs.org/)
  [![Mistral AI](https://img.shields.io/badge/AI-Mistral-purple)](https://mistral.ai/)
</div>

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Tools & Integration](#-tools--integration)
- [AI Capabilities](#-ai-capabilities)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)

## 🌟 Overview

MSH CLI is an intelligent security testing framework that combines traditional security tools with advanced AI capabilities. It provides automated analysis, real-time monitoring, and intelligent threat detection through an intuitive command-line interface.

## ✨ Features

### 🤖 AI-Powered Analysis
- Real-time command output analysis
- Contextual security implications detection
- Pattern recognition and threat correlation
- Automated vulnerability assessment
- Intelligent recommendations

### 🛡️ Security Operations
- **Terminal Monitoring**: Live analysis of activities
- **Log Analysis**: AI-enhanced log examination
- **Context-Aware Analysis**: Historical pattern matching
- **Interactive AI Chat**: Direct security consultations
- **Automated Documentation**: Report generation

### 🔍 Research & Intelligence
- Multi-platform security research
- Automated web scraping
- CVE database integration
- Security blog aggregation
- Exploit database search

## 📋 Requirements

### System Requirements
- **Operating System**:
  - Kali Linux (Recommended)
  - Ubuntu 20.04 or newer
  - Debian-based distributions
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Storage**: 2GB free space
- **Processor**: Dual-core or better
- **Internet**: Broadband connection required

### Software Dependencies
- **Node.js**: v16.0.0 or higher
- **Neo4j**: v4.4 or higher
- **Python**: v3.8 or higher
- **Chrome/Chromium**: Latest version

### API Requirements
- Mistral AI API key
- (Optional) GitHub API token
- (Optional) Google Custom Search API key

## 🚀 Installation

### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential dependencies
sudo apt install -y git nodejs npm python3 python3-pip chromium-browser
```

### 2. Neo4j Setup
```bash
# Install Neo4j
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install neo4j

# Start Neo4j service
sudo systemctl start neo4j
sudo systemctl enable neo4j
```

### 3. MSH CLI Installation
```bash
# Clone repository
git clone https://github.com/yourusername/msh-cli.git
cd msh-cli

# Install dependencies
npm install

# Make executable
chmod +x index.js

# Create symbolic link
sudo ln -s $(pwd)/index.js /usr/local/bin/msh
```

### 4. Security Tools Installation
```bash
# Install Kali tools (if not using Kali Linux)
sudo apt install -y exploitdb nmap nikto wpscan sqlmap wireshark metasploit-framework

# Install Python security packages
pip3 install requests beautifulsoup4 selenium
```

## ⚙️ Configuration

### 1. Environment Setup
```bash
# Create configuration directory
mkdir -p ~/.msh-cli

# Configure environment variables
cat << EOF > ~/.msh-cli/.env
MISTRAL_API_KEY=your_mistral_api_key
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
GITHUB_TOKEN=your_github_token
EOF
```

### 2. Neo4j Database Setup
```bash
# Set Neo4j password
cypher-shell -u neo4j -p neo4j
ALTER CURRENT USER SET PASSWORD 'your_password';
```

### 3. Browser Setup
```bash
# Install Chrome WebDriver
sudo apt install -y chromium-chromedriver
```

## 💻 Usage

### Basic Commands
```bash
# Start MSH CLI
msh

# Show help
msh help

# Start AI chat
msh chat

# Analyze system
msh anls
```

### Security Testing
```bash
# Reconnaissance
msh recon
> nmap
> target: example.com

# Vulnerability Assessment
msh vuln
> nikto
> target: https://example.com
```

### Research & Analysis
```bash
# Search security resources
msh search eternal blue

# Visit and analyze website
msh visit https://example.com

# Debug code
msh debug code
```

## 🔧 Tools & Integration

### Supported Security Tools
- **Reconnaissance**: nmap, dig, whois, sublist3r
- **Vulnerability**: nikto, wpscan, sqlmap
- **Web**: burpsuite, zaproxy, gobuster
- **Network**: wireshark, tcpdump
- **Exploitation**: metasploit, searchsploit
- **Wireless**: aircrack-ng suite

### AI Integration
- Real-time analysis
- Pattern recognition
- Threat detection
- Recommendation engine
- Code analysis

## 🤖 AI Capabilities

### Analysis Features
- Command output analysis
- Security implication detection
- Vulnerability assessment
- Risk evaluation
- Mitigation suggestions

### Intelligence
- Pattern recognition
- Historical correlation
- Threat prediction
- Learning capabilities
- Context awareness

## 🔍 Troubleshooting

### Common Issues
1. **Neo4j Connection Failed**
   ```bash
   sudo systemctl status neo4j
   sudo neo4j console  # For detailed logs
   ```

2. **Browser Automation Issues**
   ```bash
   # Check Chrome installation
   which chromium-browser
   # Update ChromeDriver
   sudo apt install -y chromium-chromedriver
   ```

3. **Permission Issues**
   ```bash
   # Fix directory permissions
   sudo chown -R $USER:$USER ~/.msh-cli
   chmod 600 ~/.msh-cli/.env
   ```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 🔐 Security

Please report security vulnerabilities to [security@msh-cli.com](mailto:security@msh-cli.com).
See our [Security Policy](SECURITY.md) for details.

## 📜 License

MSH CLI - Advanced AI-Powered Security Testing & Analysis Framework
Copyright (C) 2024 MSH CLI Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

### Third-Party Components

MSH CLI includes several third-party components that are licensed under their respective open-source licenses:

- **Node.js Packages**: Various licenses (MIT, Apache, etc.) - See `package.json` for details
- **Security Tools**: Various licenses - See individual tool documentation
- **AI Models**: Mistral AI - See Mistral's terms of service

### Contributing

By contributing to MSH CLI, you agree that your contributions will be licensed under the GPLv3 License.

For more details, see the [LICENSE](LICENSE) file in the repository.

---

<div align="center">
  <p>Made with ❤️ by Security Enthusiasts</p>
  <p>
    <a href="https://discord.gg/msh-cli">Discord</a> •
    <a href="https://twitter.com/msh_cli">Twitter</a> •
    <a href="https://msh-cli.com">Website</a>
  </p>
</div>