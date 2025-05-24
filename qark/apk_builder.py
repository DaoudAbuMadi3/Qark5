from __future__ import absolute_import

import logging
import os
import shlex
import shutil
import subprocess

from io import StringIO
import configparser

from plugins.helpers import copy_directory_to_location
from plugins.manifest_helpers import get_package_from_manifest
from xml_helpers import write_key_value_to_string_array_xml, write_key_value_to_xml

log = logging.getLogger(__name__)


COMPONENT_ENTRIES = {
    "activity": ("onCreate", "onStart"),
    "activity-alias": ("onCreate", "onStart"),
    "receiver": ("onReceive",),
    "service": ("onCreate", "onBind", "onStartCommand", "onHandleIntent"),
    "provider": ("onReceive",)
}
 
EXPLOIT_APK_TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exploit_apk")


class APKBuilder(object):
    __instance = None

    def __new__(cls, exploit_apk_path, issues, apk_name, manifest_path, sdk_path):
        if APKBuilder.__instance is None:
            APKBuilder.__instance = object.__new__(cls)
        return APKBuilder.__instance

    def __init__(self, exploit_apk_path, issues, apk_name, manifest_path, sdk_path):
        """
        Creates the APKBuilder.

        :param str exploit_apk_path: path to where the exploit apk should be built
        :param list issues: List of `Issue` found from the scanner
        :param str apk_name: name of the examined APK
        """
        self.exploit_apk_path = os.path.join(exploit_apk_path, f"{apk_name}_exploit_apk")

        if os.path.isdir(self.exploit_apk_path):
            shutil.rmtree(self.exploit_apk_path)

        try:
            copy_directory_to_location(directory_to_copy=EXPLOIT_APK_TEMPLATE_PATH, destination=self.exploit_apk_path)
        except Exception:
            log.exception("Failed to copy %s to %s", EXPLOIT_APK_TEMPLATE_PATH, self.exploit_apk_path)
            raise SystemExit("Failed to copy %s to %s", EXPLOIT_APK_TEMPLATE_PATH, self.exploit_apk_path)

        values_path = os.path.join(self.exploit_apk_path, "app", "src", "main", "res", "values")
        self.strings_xml_path = os.path.join(values_path, "strings.xml")
        self.extra_keys_xml_path = os.path.join(values_path, "extraKeys.xml")
        self.intent_ids_xml_path = os.path.join(values_path, "intentID.xml")

        self.properties_file_path = os.path.join(self.exploit_apk_path, "local.properties")
        self.sdk_path = sdk_path

        self.issues = issues
        try:
            self.package_name = get_package_from_manifest(manifest_path)
        except IOError:
            log.exception("Failed to read manifest file at %s", manifest_path)
            raise SystemExit("Failed to read manifest file at %s", manifest_path)

    def build(self):
        self._write_additional_exploits()
        self._build_apk()

    def _write_additional_exploits(self):
        for issue in self.issues:
            self._write_exported_tags(issue)

    def _write_exported_tags(self, issue):
        if issue.apk_exploit_dict:
            try:
                tag_enum = issue.apk_exploit_dict["exported_enum"]
                tag_name = issue.apk_exploit_dict["tag_name"]
                package_name = issue.apk_exploit_dict["package_name"]
            except KeyError:
                return

            arguments = issue.apk_exploit_dict.get("arguments")
            new_key = write_key_value_to_string_array_xml(
                array_name=tag_enum.parent.value,
                value=tag_enum.type.value,
                path=self.intent_ids_xml_path
            )

            if arguments is not None and tag_enum.type.value in ("activity", "broadcast", "provider", "receiver"):
                for argument in arguments:
                    write_key_value_to_string_array_xml(
                        array_name=new_key,
                        value=argument,
                        path=self.extra_keys_xml_path,
                        add_id=False
                    )

            write_key_value_to_xml(
                key=new_key,
                value=package_name + tag_name,
                path=self.strings_xml_path
            )

    def _build_apk(self):
        log.debug("Building apk...")
        current_directory = os.getcwd()
        try:
            os.chdir(self.exploit_apk_path)
            write_key_value_to_xml('packageName', self.package_name, self.strings_xml_path)
            self._write_properties_file({"sdk.dir": self.sdk_path})
            command = "./gradlew assembleDebug"
            try:
                subprocess.call(shlex.split(command))
            except Exception:
                log.exception("Error running command %s")
                raise
        except Exception:
            raise
        finally:
            os.chdir(current_directory)

    def _write_properties_file(self, dict_to_write, append=True):
        mode = "a" if append else "w"
        with open(self.properties_file_path, mode) as properties_file:
            for key, value in dict_to_write.items():
                properties_file.write(f"{key}={value}\n")

    def _read_properties_file(self):
        with open(self.properties_file_path, "r") as properties_file:
            config = StringIO()
            config.write('[dummy_header]\n')
            config.write(properties_file.read().replace('%', '%%'))
            config.seek(0, os.SEEK_SET)

            cp = configparser.ConfigParser()
            cp.read_file(config)

            return dict(cp.items('dummy_section'))
