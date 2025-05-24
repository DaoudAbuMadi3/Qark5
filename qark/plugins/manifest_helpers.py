from xml.etree import ElementTree
from xml.dom import minidom
import logging
import re

from qark.xml_helpers import get_manifest_out_of_files

log = logging.getLogger(__name__)
 
def get_package_from_manifest(manifest_path):
    """
    Get package name from AndroidManifest.xml.

    :param manifest_path: Path to the manifest file.
    :return: Package name as string.
    """
    try:
        manifest_xml = ElementTree.parse(manifest_path)
        package = manifest_xml.getroot().attrib.get("package")
        log.debug("Extracted package name: %s from manifest: %s", package, manifest_path)
        return package
    except IOError:
        log.exception("Failed to open manifest file: %s", manifest_path)
    except Exception as e:
        log.exception("Error parsing manifest file: %s", manifest_path)
    return None


def _extract_sdk_from_text(xml_content: str, attr: str) -> int:
    """
    Fallback method to extract sdk version using regex if XML parsing fails.

    :param xml_content: Raw XML content as string.
    :param attr: Attribute to search (e.g., 'minSdkVersion').
    :return: Extracted SDK version as int or 1.
    """
    match = re.search(rf'android:{attr}=["\']?(\d+)["\']?', xml_content)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    log.debug("Regex fallback: Could not extract %s from manifest", attr)
    return 1


def get_min_sdk(manifest_xml, files=None):
    """
    Get minSdkVersion from manifest; fallback to regex or default to 1 if missing or invalid.

    :param manifest_xml: XML DOM or file path.
    :param files: Optional list of files if manifest_xml is None.
    :return: Integer minSdkVersion.
    """
    if manifest_xml is None and files:
        manifest_xml = get_manifest_out_of_files(files)
    if isinstance(manifest_xml, str):
        try:
            manifest_xml = minidom.parse(manifest_xml)
        except Exception:
            try:
                with open(manifest_xml, "r", encoding="utf-8") as f:
                    return _extract_sdk_from_text(f.read(), "minSdkVersion")
            except Exception as e:
                log.debug("Fallback regex failed for minSdkVersion: %s", e)
                return 1

    try:
        sdk_section = manifest_xml.getElementsByTagName("uses-sdk")[0]
        return int(sdk_section.attributes["android:minSdkVersion"].value)
    except Exception:
        log.debug("minSdkVersion not found or invalid; defaulting to 1")
        return 1


def get_target_sdk(manifest_xml, files=None):
    """
    Get targetSdkVersion from manifest; fallback to regex or default to 1 if missing or invalid.

    :param manifest_xml: XML DOM or file path.
    :param files: Optional list of files if manifest_xml is None.
    :return: Integer targetSdkVersion.
    """
    if manifest_xml is None and files:
        manifest_xml = get_manifest_out_of_files(files)
    if isinstance(manifest_xml, str):
        try:
            manifest_xml = minidom.parse(manifest_xml)
        except Exception:
            try:
                with open(manifest_xml, "r", encoding="utf-8") as f:
                    return _extract_sdk_from_text(f.read(), "targetSdkVersion")
            except Exception as e:
                log.debug("Fallback regex failed for targetSdkVersion: %s", e)
                return 1

    try:
        sdk_section = manifest_xml.getElementsByTagName("uses-sdk")[0]
        return int(sdk_section.attributes["android:targetSdkVersion"].value)
    except Exception:
        log.debug("targetSdkVersion not found or invalid; defaulting to 1")
        return 1


if __name__ == "__main__":
    print("Testing manifest_helpers with fake XML...")
    sample_manifest = '''
    <manifest package="com.example">
        <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="30"/>
    </manifest>
    '''
    print("minSdkVersion (parsed):", _extract_sdk_from_text(sample_manifest, "minSdkVersion"))
    print("targetSdkVersion (parsed):", _extract_sdk_from_text(sample_manifest, "targetSdkVersion"))

