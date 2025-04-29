from setuptools import setup, find_packages
import os
import io

QARK_DIR = "qark"
LIB_DIR = os.path.join(QARK_DIR, "lib")

exploit_apk_files = [os.path.join(dir_path, filename).replace(os.path.join(QARK_DIR, ""), "")
                     for dir_path, _, files in os.walk(os.path.join(QARK_DIR, "exploit_apk"))
                     for filename in files]

with io.open('README.rst', 'rt', encoding='utf8') as f:
    long_description = f.read()

setup(
    name="qark",
    version="5.0.0",
    packages=find_packages(exclude=["tests*"]),
    package_dir={QARK_DIR: QARK_DIR},
    package_data={
        QARK_DIR: [
            os.path.join("lib", "apktool", "apktool.jar"),
            os.path.join("lib", "jadx", "**", "*"),
            os.path.join("templates", "*.jinja"),
        ] + exploit_apk_files,
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
        qark=qark.qark:cli""",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Unix",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.11",
    ]
)
