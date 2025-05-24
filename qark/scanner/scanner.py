from __future__ import absolute_import

import logging
from os import walk, path

from qark.scanner.plugin import CoroutinePlugin, JavaASTPlugin, ManifestPlugin, PluginObserver
from qark.scanner.plugin import get_plugin_source, get_plugins
from qark.utils import is_java_file

log = logging.getLogger(__name__)

PLUGIN_CATEGORIES = ("manifest", "broadcast", "file", "crypto", "intent", "cert", "webview", "generic")
 
class Scanner(object):
    def __init__(self, manifest_path, path_to_source):
        self.files = set()
        self.issues = []
        self.manifest_path = manifest_path
        self.path_to_source = path_to_source
        self._gather_files()

    def run(self):
        log.debug("Starting scanner run...")
        plugins = []
        for category in PLUGIN_CATEGORIES:
            plugin_source = get_plugin_source(category)
            log.debug("Loading plugins for category: %s", category)

            if category == "manifest":
                manifest_plugins = get_plugins(category)
                ManifestPlugin.update_manifest(self.manifest_path)
                if ManifestPlugin.manifest_xml is not None:
                    for plugin in [plugin_source.load_plugin(name).plugin for name in manifest_plugins]:
                        plugin.all_files = self.files
                        plugin.run()
                        self.issues.extend(plugin.issues)
                        log.debug("Ran manifest plugin: %s; issues found: %d", plugin.name, len(plugin.issues))
                    continue

            for plugin_name in get_plugins(category):
                plugins.append(plugin_source.load_plugin(plugin_name).plugin)

        log.debug("Total plugins loaded (non-manifest): %d", len(plugins))
        self._run_checks(plugins)

    def _run_checks(self, plugins):
        current_file_subject = Subject()
        plugins = list(observer for observer in plugins if isinstance(observer, PluginObserver))
        coroutine_plugins = list(coro for coro in plugins if isinstance(coro, CoroutinePlugin))
        log.debug("Registered %d observer plugins, %d coroutine plugins", len(plugins), len(coroutine_plugins))

        for plugin in plugins:
            current_file_subject.register(plugin)

        for filepath in self.files:
            log.debug("Scanning file: %s", filepath)
            current_file_subject.notify(filepath)
            notify_coroutines(coroutine_plugins)
            current_file_subject.reset()

        for plugin in plugins:
            if hasattr(plugin, 'finalize') and callable(getattr(plugin, 'finalize')):
                plugin.finalize()
                log.debug("Finalized plugin: %s", plugin.name)

        for plugin in plugins:
            self.issues.extend(plugin.issues)
            log.debug("Collected %d issues from plugin: %s", len(plugin.issues), plugin.name)

    def _gather_files(self):
        if is_java_file(self.path_to_source):
            self.files.add(self.path_to_source)
            log.debug("Added single java file: %s", self.path_to_source)
            return

        try:
            for (dir_path, _, file_names) in walk(self.path_to_source):
                for file_name in file_names:
                    self.files.add(path.join(dir_path, file_name))
            log.debug("Collected %d files from path: %s", len(self.files), self.path_to_source)
        except AttributeError:
            log.debug("No files found; directory missing or invalid.")

class Subject(object):
    def __init__(self):
        self.observers = []

    def register(self, observer):
        self.observers.append(observer)
        log.debug("Registered observer: %s", observer.name)

    def unregister(self, observer):
        self.observers.remove(observer)
        log.debug("Unregistered observer: %s", observer.name)

    def notify(self, file_path):
        for observer in self.observers:
            observer.update(file_path, call_run=True)

    def reset(self):
        for observer in self.observers:
            observer.reset()
        log.debug("Reset all observer states.")

def notify_coroutines(coroutine_plugins):
    if JavaASTPlugin.java_ast is not None:
        coroutines_to_run = []
        for plugin in coroutine_plugins:
            if plugin.can_run_coroutine():
                coroutines_to_run.append(plugin.prime_coroutine())
                log.debug("Primed coroutine: %s", plugin.name)

        for path, node in JavaASTPlugin.java_ast:
            for coroutine in coroutines_to_run:
                coroutine.send((path, node))

