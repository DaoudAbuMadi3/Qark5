Quick Android Review Kit 🛡️
===========================
[![QARK5 - Quick Android Review Kit 🛡️](https://capsule-render.vercel.app/api?text=QARK5%20Architectur&animation=fadeIn&type=waving&color=gradient&height=100)](https://github.com/DaoudAbuMadi3/Qark5)





[![QARK5 - Mobile Pentesting Tool](https://github.com/DaoudAbuMadi3/Qark5/blob/main/docs/System_Arch.png
)](https://github.com/DaoudAbuMadi3/Qark5)



[![GitHub Stars](https://img.shields.io/github/stars/DaoudAbuMadi3/Qark5?style=social)](https://github.com/DaoudAbuMadi3/Qark5/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/DaoudAbuMadi3/Qark5?style=social)](https://github.com/DaoudAbuMadi3/Qark5/network/members)

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

[![Python: 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![OS: Linux + Windows](https://img.shields.io/badge/OS-Linux%20%2B%20Windows-blue.svg)](https://github.com/DaoudAbuMadi3/Qark5#installation)

---


## About the Project
🌟 QARK5 is an enhanced version of the Quick Android Review Kit, designed to identify security vulnerabilities in Android applications. This tool analyzes both source code and compiled applications (APKs), generating executable Proof-of-Crisis (PoC) tools and/or ADB commands. Unlike traditional security tools, QARK5 runs on unrooted devices, focusing on vulnerabilities that can be exploited under normal conditions. 🚀



## Table of Contents
- [About the Project](#about-the-project)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Results](#results)
- [Exploit APK](#exploit-apk)
- [Checks](#checks)
- [Notice](#notice)
- [License](#license)


## Getting Started
These instructions will get you a copy of the project up and running on your local machine.

## Requirements

🔧 Python 3.11

🖥️ Linux or Windows operating system

📦 Virtual environment

🔍 Jadx decompiler (version 1.5.1)


## Installation  
[Installation ](#installation)

### Linux Installation
```bash
# Create and activate virtual environment
python3 -m venv env1
source env1/bin/activate

# Clone the repository
git clone https://github.com/DaoudAbuMadi3/Qark5.git

# Download jadx
cd Qark5/qark/lib
wget https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
mkdir jadx-1.5.1
mv jadx-1.5.1.zip jadx-1.5.1
cd jadx-1.5.1
unzip jadx-1.5.1.zip

# Install requirements
cd ../../..
pip install -r requirements.txt
pip install .
```

### Windows Installation
```bash
# Set encoding in PowerShell
chcp 65001
$OutputEncoding = [System.Text.UTF8Encoding]::new()

# Create and activate virtual environment
python3 -m venv env1
./env1/Scripts/Activate.ps1

# Clone the repository
git clone https://github.com/DaoudAbuMadi3/Qark5.git

# Download jadx
cd Qark5/qark/lib
# Download jadx-1.5.1.zip from https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
# Extract it to this directory

# Install requirements
cd ../../..
pip install -r requirements.txt
pip install .
```

## Usage
```bash
# Static Analysis
qark --analyze

# Select file type (.apk or .java)
# Enter absolute file path
```

## Features
🌟 Analyzes both APK files and Java source code
🎯 Creates deployable PoC APKs and ADB commands
📱 Works on unrooted devices
🎯 Free and open-source
📚 Educational focus with detailed vulnerability explanations
🔍 Automates multiple decompilers for superior results
📊 Generates HTML and CSV reports




## Results
📊 A report is generated in HTML and CSV format, which can be selected through the `--report-type` flag.

## Exploit APK
🎯 QARK can generate a basic exploit APK for a few of the vulnerabilities that have been found.

To generate the exploit APK there are a few steps to follow. You need to have the Android SDK v21 and build-tools v21.1.2

1. Install the android SDK, you can get it under the 'command line tools': https://developer.android.com/studio/#downloads
2. Unzip the android SDK
3. Go into the new directory and generate the licenses with `bin/sdkmanager --licenses`
4. Make sure the generated licenses are in the android SDK directory.
5. Install the SDK and the proper build-tools version: `bin/sdkmanager --install "platforms;android-21" "sources;android-21" "build-tools;21.1.2"`

## Checks
🔍 QARK is an easy to use tool capable of finding common security vulnerabilities in Android applications. Unlike commercial products, it is 100% free to use. QARK features educational information allowing security reviewers to locate precise, in-depth explanations of the vulnerabilities. QARK automates the use of multiple decompilers, leveraging their combined outputs, to produce superior results, when decompiling APKs. Finally, the major advantage QARK has over traditional tools, that just point you to possible vulnerabilities, is that it can produce ADB commands, or even fully functional APKs, that turn hypothetical vulnerabilities into working "POC" exploits.

Included in the types of security vulnerabilities this tool attempts to find are:

- Inadvertently exported components
- Improperly protected exported components
- Intents which are vulnerable to interception or eavesdropping
- Improper x.509 certificate validation
- Creation of world-readable or world-writeable files
- Activities which may leak data
- The use of Sticky Intents
- Insecurely created Pending Intents
- Sending of insecure Broadcast Intents
- Private keys embedded in the source
- Weak or improper cryptography use
- Potentially exploitable WebView configurations
- Exported Preference Activities
- Tapjacking
- Apps which enable backups
- Apps which are debuggable
- Apps supporting outdated API versions, with known vulnerabilities

## Notice
⚠️ Note: QARK decompiles Android applications back to raw source code. Please do not use this tool if this may be considered illegal in your jurisdiction. If you are unsure, seek legal counsel.

If you run into issues on OSX, especially relating to the outbound call to the Play Store, or the downloading of the SDK, it is
likely due to your Python/OpenSSL configuration and the fact that recent changes in OSX impacted Python installed via brew. Nuking your
Python installation(s) and re-installing from source may fix your issues.

## License
📜 Copyright 2015 LinkedIn Corp.  All rights reserved.

📜 Copyright 2015 LinkedIn Corp. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
You may obtain a copy of the License `here <http://www.apache.org/licenses/LICENSE-2.0/>`_.
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

---
