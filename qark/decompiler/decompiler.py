import logging
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import zipfile
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Callable, Dict, Any

from utils import is_java_file

log = logging.getLogger(__name__)

OS = platform.system()
JAVA_VERSION_REGEX = r'"(\d+\.\d+\.\d+)"|(\d+)'  # Matches "1.7.0", "11.0.8", or "17"
LIB_PATH = Path(__file__).resolve().parent / "lib"
APK_TOOL_PATH = LIB_PATH / "apktool" / "apktool.jar"
JADX_PATH = os.path.join(LIB_PATH, "jadx", "bin", "jadx")

APK_TOOL_COMMAND = (
    "java -Djava.awt.headless=true -jar {apktool_jar} "
    "d {apk} --no-src --force -m -o {out_dir}"
)

class Decompiler:
    def __init__(self, path_to_source: str, build_directory: str = None):
        if not os.path.exists(path_to_source):
            raise ValueError(f"Invalid path: {path_to_source} does not exist")

        self.path_to_source = os.path.abspath(path_to_source)
        self.build_directory = os.path.join(build_directory, "qark") if build_directory else os.path.join(os.path.dirname(self.path_to_source), "qark")

        try:
            os.makedirs(self.build_directory, exist_ok=True)
        except PermissionError as e:
            raise PermissionError(f"Cannot create build directory {self.build_directory}: {e}")

        if os.path.isdir(path_to_source) or is_java_file(path_to_source):
            self.source_code = True
            self.manifest_path = None
            log.debug("Source is Java, skipping APK decompilation")
            return

        self.source_code = False
        self.apk_name = os.path.splitext(os.path.basename(path_to_source))[0]
        self._validate_tools()
        self.manifest_path = self.run_apktool()
        self.run_jadx()

    def run(self):
        if self.source_code:
            log.info("Source is Java, no binary analysis will be performed.")
            return
        log.info("Decompilation pipeline completed successfully.")

    def run_apktool(self) -> str:
        log.info("Running apktool...")
        self._check_java_version()

        output_path = os.path.join(self.build_directory, "apktool.jar")
        cmd = APK_TOOL_COMMAND.format(
            apktool_jar=APK_TOOL_PATH,
            apk=self.path_to_source,
            out_dir=output_path
        )
        try:
            subprocess.check_call(shlex.split(cmd))
            manifest_src = os.path.join(output_path, "AndroidManifest.xml")
            manifest_dest = os.path.join(self.build_directory, "AndroidManifest.xml")
            if not os.path.exists(manifest_src):
                raise FileNotFoundError("AndroidManifest.xml not found in apktool output")
            shutil.move(manifest_src, manifest_dest)
            shutil.rmtree(output_path, ignore_errors=True)
        except subprocess.CalledProcessError as e:
            log.error("apktool failed with exit code %s", e.returncode)
            raise RuntimeError("apktool execution failed")

        return manifest_dest

    def run_jadx(self):
        log.info("Running jadx...")
        output_dir = os.path.join(self.build_directory, "jadx_output")
        os.makedirs(output_dir, exist_ok=True)

        cmd = f"{JADX_PATH} -d {output_dir} {self.path_to_source}"
        try:
            subprocess.check_call(shlex.split(cmd))
        except subprocess.CalledProcessError as e:
            log.error("jadx failed with exit code %s", e.returncode)
            raise RuntimeError("jadx execution failed")

    def _check_java_version(self):
        try:
            full_version = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT).decode("utf-8")
            version_match = re.search(JAVA_VERSION_REGEX, full_version)
            if not version_match:
                raise RuntimeError("Could not parse Java version")
            version = version_match.group(1) or version_match.group(2)
            major_version = int(version.split(".")[0]) if "." in version else int(version)
            if major_version < 7:
                raise RuntimeError(f"Java 7+ is required for apktool, found version {version}")
        except subprocess.CalledProcessError as e:
            log.error("Java check failed")
            raise RuntimeError("Error validating Java version")

    def _validate_tools(self):
        if not os.path.exists(APK_TOOL_PATH):
            raise FileNotFoundError(f"apktool not found at {APK_TOOL_PATH}")
        if not os.path.exists(JADX_PATH):
            raise FileNotFoundError(f"jadx not found at {JADX_PATH}")
        if not os.access(JADX_PATH, os.X_OK):
            os.chmod(JADX_PATH, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)


def unzip_file(file_to_unzip: str, destination_to_unzip: str = "unzip_apk"):
    try:
        os.makedirs(destination_to_unzip, exist_ok=True)
        with zipfile.ZipFile(file_to_unzip, "r") as zipped_apk:
            zipped_apk.extractall(path=destination_to_unzip)
    except zipfile.BadZipFile:
        log.error("Invalid APK file: %s", file_to_unzip)
        raise RuntimeError("Failed to extract APK: Invalid ZIP file")
