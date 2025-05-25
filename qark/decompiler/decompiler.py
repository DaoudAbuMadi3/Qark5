import logging
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
 
from qark.utils import is_java_file
 
log = logging.getLogger(__name__)

OS = platform.system()
JAVA_VERSION_REGEX = r'"(\d+\.\d+\.\d+)"|(\d+)'  # Matches "1.7.0", "11.0.8", or "17"

# ✅ Use env var if defined, fallback to relative path
LIB_PATH = Path(os.environ.get("QARK_LIB_PATH", Path(__file__).resolve().parent.parent / "lib"))

# Configure platform-specific paths and commands
if OS == "Windows":
    APK_TOOL_PATH = LIB_PATH / "apktool" / "apktool.jar"
    JADX_PATH = LIB_PATH / "jadx-1.5.1" / "bin" / "jadx.bat"
    DEX2JAR_PATH = LIB_PATH / "dex2jar" / "d2j-dex2jar.bat"
    CFR_JAR = LIB_PATH / "cfr.jar"
    PROCYON_JAR = LIB_PATH / "procyon.jar"

    # Windows-specific command formatting
    APK_TOOL_COMMAND = (
        'java -Djava.awt.headless=true -jar "{apktool_jar}" '
        'd "{apk}" --no-src --force -m -o "{out_dir}"'
    )
else:  # Linux, MacOS, etc.
    APK_TOOL_PATH = LIB_PATH / "apktool" / "apktool.jar"
    JADX_PATH = LIB_PATH / "jadx-1.5.1" / "bin" / "jadx"
    DEX2JAR_PATH = LIB_PATH / "dex2jar" / "d2j-dex2jar.sh"
    CFR_JAR = LIB_PATH / "cfr.jar"
    PROCYON_JAR = LIB_PATH / "procyon.jar"

    # Linux-specific command formatting
    APK_TOOL_COMMAND = (
        "java -Djava.awt.headless=true -jar {apktool_jar} "
        "d {apk} --no-src --force -m -o {out_dir}"
    )

class Decompiler:
    def __init__(self, path_to_source: str, build_directory: str = None):
        if not os.path.exists(path_to_source):
            raise ValueError(f"Invalid path: {path_to_source} does not exist")

        self.path_to_source = os.path.abspath(path_to_source)
        self.build_directory = Path(build_directory or Path(self.path_to_source).parent / "qark").resolve()
        self.decompiled_java_path = None  # 🔑 Holds the final Java source path
        self.decompiler_used = None       # 🛠️ Tracks which tool was used (jadx, cfr, or procyon)

        try:
            os.makedirs(self.build_directory, exist_ok=True)
        except PermissionError as e:
            raise PermissionError(f"Cannot create build directory {self.build_directory}: {e}")

        if os.path.isdir(path_to_source) or is_java_file(path_to_source):
            self.source_code = True
            self.manifest_path = None
            log.debug("📄 Source is Java, skipping APK decompilation")
            return

        self.source_code = False
        self.apk_name = Path(path_to_source).stem
        log.info("🚀 Initializing decompilation pipeline for APK: %s", self.apk_name)
        self._validate_tools()

    def run(self):
        if self.source_code:
            log.info("Source is Java, no binary analysis will be performed.")
            return

        self.manifest_path = self.run_apktool()

        try:
            self.run_jadx()
        except Exception as e:
            log.warning(f"⚠️ JADX failed: {e}, falling back to unzip + dex2jar + CFR/Procyon pipeline...")
            try:
                self.run_dex2jar_pipeline()
            except Exception as fallback_error:
                log.error(f"❌ All decompilation attempts failed: {fallback_error}")

    def run_apktool(self):
        log.info("🔧 Running apktool... (Extracting resources and AndroidManifest.xml)")
        self._check_java_version()

        apktool_out = self.build_directory / "apktool_out"
        
        # Format command according to the OS
        cmd = APK_TOOL_COMMAND.format(
            apktool_jar=APK_TOOL_PATH,
            apk=self.path_to_source,
            out_dir=apktool_out
        )

        try:
            # Execute differently depending on OS
            if OS == "Windows":
                # On Windows, use shell=True and don't split the command
                subprocess.check_call(cmd, shell=True)
            else:
                # On Linux/Mac, use shlex to split and shell=False
                subprocess.check_call(shlex.split(cmd))
                
            manifest_src = apktool_out / "AndroidManifest.xml"
            manifest_dest = self.build_directory / "AndroidManifest.xml"
            
            if not manifest_src.exists():
                raise FileNotFoundError("AndroidManifest.xml not found in apktool output")
                
            shutil.move(str(manifest_src), str(manifest_dest))
            
            # Copy files safely using pathlib methods
            for item in apktool_out.glob('*'):
                if item.is_dir():
                    dest_dir = self.build_directory / item.name
                    if not dest_dir.exists():
                        shutil.copytree(item, dest_dir)
                else:
                    shutil.copy2(item, self.build_directory)
                    
            shutil.rmtree(apktool_out, ignore_errors=True)
            log.info("📄 AndroidManifest.xml extracted successfully")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"apktool execution failed: {e}")

        return str(manifest_dest)

    def run_jadx(self):
        log.info("🧩 Running JADX decompiler... (Attempting direct Java decompilation)")
        jadx_out = self.build_directory / "jadx_out"
        
        if OS == "Windows":
            cmd = f'"{JADX_PATH}" --no-res -d "{jadx_out}" "{self.path_to_source}"'
            subprocess.check_call(cmd, shell=True)
        else:
            cmd = f"{JADX_PATH} --no-res -d {jadx_out} {self.path_to_source}"
            subprocess.check_call(shlex.split(cmd))
            
        log.info("✅ JADX decompilation completed")
        self.decompiled_java_path = jadx_out
        self.decompiler_used = "jadx"

    def run_dex2jar_pipeline(self):
        log.info("📦 Fallback: Extracting APK using zipfile...")
        unzip_out = self.build_directory / "unzip_out"
        unzip_out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.path_to_source, 'r') as zip_ref:
            zip_ref.extractall(unzip_out)

        dex_files = list(unzip_out.glob("classes*.dex"))
        if not dex_files:
            raise FileNotFoundError("No classes.dex files found")

        log.info("🔁 Converting DEX to JAR using dex2jar...")
        dex2jar_out = self.build_directory / "dex2jar_out"
        dex2jar_out.mkdir(parents=True, exist_ok=True)

        for dex in dex_files:
            jar_output = dex2jar_out / f"{dex.name}.dex2jar.jar"
            
            if OS == "Windows":
                dex2jar_cmd = f'"{DEX2JAR_PATH}" -o "{jar_output}" "{dex}"'
            else:
                dex2jar_cmd = f"bash {DEX2JAR_PATH} -o {jar_output} {dex}"
                
            subprocess.check_call(dex2jar_cmd, shell=True)

            try:
                self.run_cfr(jar_output)
                return
            except Exception as e:
                log.warning(f"⚠️ CFR failed: {e}, trying Procyon...")
                self.run_procyon(jar_output)
                return

    def run_cfr(self, jar_path):
        log.info("📖 Decompiling JAR using CFR...")
        cfr_out = self.build_directory / "cfr_out"
        cfr_out.mkdir(parents=True, exist_ok=True)
        
        if OS == "Windows":
            cmd = f'java -jar "{CFR_JAR}" "{jar_path}" --outputdir "{cfr_out}"'
            subprocess.check_call(cmd, shell=True)
        else:
            cmd = f"java -jar {CFR_JAR} {jar_path} --outputdir {cfr_out}"
            subprocess.check_call(shlex.split(cmd))
            
        self.decompiled_java_path = cfr_out
        self.decompiler_used = "cfr"

    def run_procyon(self, jar_path):
        log.info("📖 Decompiling JAR using Procyon...")
        procyon_out = self.build_directory / "procyon_out"
        procyon_out.mkdir(parents=True, exist_ok=True)
        
        if OS == "Windows":
            cmd = f'java -jar "{PROCYON_JAR}" "{jar_path}" --loglevel WARNING -o "{procyon_out}"'
            subprocess.check_call(cmd, shell=True)
        else:
            cmd = f"java -jar {PROCYON_JAR} {jar_path} --loglevel WARNING -o {procyon_out}"
            subprocess.check_call(shlex.split(cmd))
            
        self.decompiled_java_path = procyon_out
        self.decompiler_used = "procyon"

    def _check_java_version(self):
        try:
            full_version = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT).decode("utf-8")
            version_match = re.search(JAVA_VERSION_REGEX, full_version)
            if not version_match:
                raise RuntimeError("Could not parse Java version")
            version = version_match.group(1) or version_match.group(2)
            major_version = int(version.split(".")[0]) if "." in version else int(version)
            if major_version < 7:
                raise RuntimeError(f"Java 7+ is required, found version {version}")
            log.info("☕ Java version check passed: %s", version)
        except subprocess.CalledProcessError:
            raise RuntimeError("Error validating Java version")

    def _validate_tools(self):
        log.info("🔍 Validating tool paths...")
        for tool_path, name in [(APK_TOOL_PATH, "apktool"), (JADX_PATH, "jadx"), (DEX2JAR_PATH, "dex2jar")]:
            if not os.path.exists(tool_path):
                raise FileNotFoundError(f"{name} not found at {tool_path}")
        
        # Only set executable permissions on Linux/Mac
        if OS != "Windows" and not os.access(JADX_PATH, os.X_OK):
            os.chmod(JADX_PATH, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
        log.info("✅ All required tools are available")