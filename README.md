# QARK5 - Quick Android Review Kit
[![QARK5 Logo](https://user-images.githubusercontent.com/46517096/166974368-9798f39f-1f46-499c-b14e-81f0a3f83a06.png)](https://github.com/DaoudAbuMadi3/Qark5)

[![GitHub Stars](https://img.shields.io/github/stars/DaoudAbuMadi3/Qark5?style=social)](https://github.com/DaoudAbuMadi3/Qark5/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/DaoudAbuMadi3/Qark5?style=social)](https://github.com/DaoudAbuMadi3/Qark5/network/members)

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![OS: Linux + Windows](https://img.shields.io/badge/OS-Linux%20%2B%20Windows-blue.svg)](https://github.com/DaoudAbuMadi3/Qark5#installation)

---

## Table of Contents
- [About the Project](#about-the-project)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Contributing](#contributing)
- [License](#license)

## About the Project
[![QARK5 Architecture](https://capsule-render.vercel.app/api?text=QARK5%20Architecture&animation=fadeIn&type=waving&color=gradient&height=100)](https://github.com/DaoudAbuMadi3/Qark5)

QARK5 is an enhanced version of the Quick Android Review Kit, designed to identify security vulnerabilities in Android applications. This tool analyzes both source code and packaged APKs, creating proof-of-concept deployable APKs and/or ADB commands to demonstrate found vulnerabilities. Unlike traditional security tools, QARK5 works on unrooted devices, focusing on vulnerabilities that can be exploited under normal conditions.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites
* Python 3.11
* Linux or Windows operating system
* Virtual environment
* Jadx decompiler (version 1.5.1)

### Installation
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

## Usage
```bash
# Static Analysis
qark --analyze

# Select file type (.apk or .java)
# Enter absolute file path
```

## Features
* Analyzes both APK files and Java source code
* Creates deployable PoC APKs and ADB commands
* Works on unrooted devices
* Free and open-source
* Educational focus with detailed vulnerability explanations
* Automates multiple decompilers for superior results
* Generates HTML and CSV reports

## Requirements
* Python 3.11
* Linux or Windows operating system
* Virtual environment
* Jadx decompiler (version 1.5.1)

## Installation
[Installation instructions are above](#installation)

## Contributing
Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
Distributed under the MIT License. See `LICENSE` for more information.

## Contact
[Your Name](https://github.com/DaoudAbuMadi3) - [Twitter Handle](https://twitter.com/your_handle) - [email@example.com](mailto:email@example.com)

Project Link: [https://github.com/DaoudAbuMadi3/Qark5](https://github.com/DaoudAbuMadi3/Qark5)

---

[![Snake animation](https://github.com/DaoudAbuMadi3/Qark5/blob/output/github-contribution-grid-snake.svg)](https://github.com/DaoudAbuMadi3/Qark5)
