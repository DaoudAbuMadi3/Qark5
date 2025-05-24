from setuptools import setup, find_packages
import os
import io
import platform


QARK_DIR = "qark"
LIB_DIR = os.path.join(QARK_DIR, "lib")

# Collect exploit_apk files in a way that is compatible with both systems.
exploit_apk_files = []
for dir_path, _, files in os.walk(os.path.join(QARK_DIR, "exploit_apk")):
    for filename in files:
        # Use relative path
        rel_path = os.path.join(dir_path, filename).replace(QARK_DIR + os.sep, "")
        # Convert paths to be compatible with the current operating system.
        normalized_path = os.path.normpath(rel_path)
        exploit_apk_files.append(normalized_path)

# Read the README file
try:
    with io.open('README.rst', 'rt', encoding='utf8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "QARK - Quick Android Review Kit"

# Define library paths in a way that is compatible with both systems.
package_data_paths = [
    os.path.normpath(os.path.join("lib", "apktool", "apktool.jar")),
    os.path.normpath(os.path.join("lib", "jadx-1.5.1", "**", "*")),
    os.path.normpath(os.path.join("lib", "dex2jar", "**", "*")),
    os.path.normpath(os.path.join("lib", "cfr.jar")),
    os.path.normpath(os.path.join("lib", "procyon.jar")),
    os.path.normpath(os.path.join("templates", "*.jinja")),
]

# Add additional Windows-specific paths
if platform.system() == "Windows":
    package_data_paths.extend([
        os.path.normpath(os.path.join("lib", "apktool", "apktool.bat")),
        os.path.normpath(os.path.join("lib", "jadx-1.5.1", "bin", "*.bat")),
        os.path.normpath(os.path.join("lib", "dex2jar", "*.bat")),
    ])

setup(
    name="qark",
    version="5.0.0",
    packages=find_packages(exclude=["tests*"]),
    package_dir={QARK_DIR: QARK_DIR},
    package_data={
        QARK_DIR: package_data_paths + exploit_apk_files,
    },
    install_requires=[
        "requests[security]>=2.31.0",
        "pluginbase>=1.0.1",
        "jinja2>=3.1.2",
        "javalang==0.13.0",
        "click>=8.1.7",
        "cryptography>=42.0.0",
        "setuptools>=69.0.3",
        "typing-extensions>=4.10.0",
        "xmltodict>=0.13.0",
        "lxml>=5.1.0"
    ],
    description="Android static code analyzer",
    long_description=long_description,
    keywords="android security qark exploit",
    python_requires=">=3.6",
    entry_points="""
        [console_scripts]
        qark=qark.qark:cli
    """,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3.11",
    ]
)
