from abc import ABC, abstractmethod
import logging
import os
from xml.dom import minidom

import javalang
from pluginbase import PluginBase

from qark.plugins.manifest_helpers import get_min_sdk, get_target_sdk, get_package_from_manifest
from qark.utils import is_java_file

log = logging.getLogger(__name__)

plugin_base = PluginBase(package="qark.custom_plugins")
BLACKLISTED_PLUGIN_MODULES = {"helpers"}
 
def get_plugin_source(category=None):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins")
    if category:
        path = os.path.join(path, category)

    try:
        log.debug("Loading plugins from path: %s", path)
        return plugin_base.make_plugin_source(searchpath=[path], persist=True)
    except Exception:
        log.exception("Failed to get plugins from path: %s", path)
        raise SystemExit("Failed to get plugins; check path.")

def get_plugins(category=None):
    plugins = get_plugin_source(category).list_plugins()
    valid_plugins = [p for p in plugins if p not in BLACKLISTED_PLUGIN_MODULES]
    log.debug("Discovered plugins in category '%s': %s", category, valid_plugins)
    return valid_plugins

class BasePlugin(ABC):
    def __init__(self, name, category, description=None, **kwargs):
        self.category = category
        self.name = name
        self.description = description
        self.issues = []
        log.debug("Initialized plugin: %s (category: %s)", name, category)
        super().__init__(**kwargs)

    @abstractmethod
    def run(self):
        raise NotImplementedError()

class PluginObserver(BasePlugin, ABC):
    @abstractmethod
    def update(self, *args, **kwargs):
        pass

    @abstractmethod
    def reset(self):
        pass

class FilePathPlugin(PluginObserver, ABC):
    file_path = None
    has_been_set = False

    def update(self, file_path, call_run=False):
        if not file_path:
            FilePathPlugin.file_path = None
            return

        if not self.has_been_set:
            FilePathPlugin.file_path = file_path
            FilePathPlugin.has_been_set = True
            log.debug("FilePathPlugin set for file: %s", file_path)

        if call_run:
            self.run()

    @classmethod
    def reset(cls):
        log.debug("Reset FilePathPlugin state")
        FilePathPlugin.file_path = None
        FilePathPlugin.has_been_set = False

class FileContentsPlugin(FilePathPlugin, ABC):
    file_contents = None
    readable = True

    def update(self, file_path, call_run=False):
        if not self.readable:
            return

        if self.file_contents is None:
            super().update(file_path)
            try:
                with open(self.file_path, "r") as f:
                    FileContentsPlugin.file_contents = f.read()
                    log.debug("Read file contents for: %s", self.file_path)
            except IOError:
                log.debug("Failed to read file: %s", self.file_path)
                FileContentsPlugin.readable = False
                return
            except UnicodeDecodeError:
                try:
                    with open(self.file_path, "r", encoding="ISO-8859-1") as f:
                        FileContentsPlugin.file_contents = f.read()
                        log.debug("Read file contents (ISO-8859-1) for: %s", self.file_path)
                except Exception:
                    log.debug("Failed to read file (any encoding): %s", self.file_path)
                    FileContentsPlugin.readable = False
                    return
        if call_run and self.file_contents:
            self.run()

    @classmethod
    def reset(cls):
        log.debug("Reset FileContentsPlugin state")
        FileContentsPlugin.file_contents = None
        FileContentsPlugin.readable = True
        super().reset()

class JavaASTPlugin(FileContentsPlugin, ABC):
    java_ast = None
    parseable = True

    def update(self, file_path, call_run=False):
        if not self.parseable:
            return

        if self.java_ast is None and is_java_file(file_path):
            super().update(file_path, call_run=False)
            if self.file_contents:
                try:
                    JavaASTPlugin.java_ast = javalang.parse.parse(self.file_contents)
                    log.debug("Parsed AST for: %s", self.file_path)
                except (javalang.parser.JavaSyntaxError, IndexError):
                    log.debug("Unable to parse AST: %s", self.file_path)
                    JavaASTPlugin.parseable = False
        if call_run and self.java_ast:
            try:
                self.run()
            except Exception:
                log.exception("Plugin run failed on: %s", self.file_path)

    @classmethod
    def reset(cls):
        log.debug("Reset JavaASTPlugin state")
        JavaASTPlugin.java_ast = None
        JavaASTPlugin.parseable = True
        super().reset()

class CoroutinePlugin(JavaASTPlugin):
    def can_run_coroutine(self):
        return True

    def run(self):
        if self.can_run_coroutine():
            coroutine = self.prime_coroutine()
            for path, node in self.java_ast:
                coroutine.send((path, node))

    def prime_coroutine(self):
        coroutine = self.run_coroutine()
        next(coroutine)
        return coroutine

    @abstractmethod
    def run_coroutine(self):
        pass

    def update(self, file_path, call_run=False):
        super().update(file_path)

class ManifestPlugin(BasePlugin, ABC):
    manifest_xml = None
    manifest_path = None
    min_sdk = -1
    target_sdk = -1
    package_name = "PACKAGE_NOT_FOUND"

    @classmethod
    def update_manifest(cls, path_to_manifest):
        cls.manifest_path = path_to_manifest
        try:
            cls.manifest_xml = minidom.parse(path_to_manifest)
            log.debug("Parsed manifest XML: %s", path_to_manifest)
        except Exception:
            log.debug("Failed to parse manifest XML: %s", path_to_manifest)
            cls.manifest_xml = None
            return

        try:
            cls.min_sdk = get_min_sdk(cls.manifest_path)
            cls.target_sdk = get_target_sdk(cls.manifest_path)
            log.debug("Manifest minSdk: %s, targetSdk: %s", cls.min_sdk, cls.target_sdk)
        except Exception:
            cls.min_sdk = cls.target_sdk = 1
            log.debug("Defaulted minSdk and targetSdk to 1")

        try:
            cls.package_name = get_package_from_manifest(cls.manifest_path)
            log.debug("Manifest package: %s", cls.package_name)
        except IOError:
            log.debug("Failed to extract package name; using default.")
            cls.package_name = "PACKAGE_NOT_FOUND"

    @abstractmethod
    def run(self):
        pass

