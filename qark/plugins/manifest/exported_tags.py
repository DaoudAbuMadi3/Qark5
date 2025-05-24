# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-5: Exported components (activities, services, receivers) must be protected using android:permission.
# This plugin analyzes AndroidManifest.xml and flags exported components lacking protection, considering SDK version and broadcast sensitivity.

from qark.plugins.manifest_helpers import get_min_sdk, get_target_sdk, get_package_from_manifest
from qark.plugins.helpers import java_files_from_files
from qark.scanner.plugin import ManifestPlugin
from qark.issue import Severity, Issue
 
import os
import logging
from typing import Dict, List, Optional, Set
from enum import Enum
import javalang
from javalang.tree import Literal, MethodDeclaration, MethodInvocation

log = logging.getLogger(__name__)

# Component lifecycle methods that handle external data
COMPONENT_ENTRIES = {
    "activity": {"onCreate", "onStart", "onResume", "onNewIntent"},
    "activity-alias": {"onCreate", "onStart", "onResume", "onNewIntent"},
    "receiver": {"onReceive"},
    "service": {"onCreate", "onBind", "onStartCommand", "onHandleIntent"},
    "provider": {"onCreate", "query", "insert", "update", "delete", "getType"}
}

# Methods that extract data from intents/bundles - potential injection points
EXTRAS_METHOD_NAMES = [
    'getExtras', 'getStringExtra', 'getIntExtra', 'getIntArrayExtra',
    'getFloatExtra', 'getFloatArrayExtra', 'getDoubleExtra', 'getDoubleArrayExtra',
    'getCharExtra', 'getCharArrayExtra', 'getByteExtra', 'getByteArrayExtra',
    'getBundleExtra', 'getBooleanExtra', 'getBooleanArrayExtra', 'getCharSequenceArrayExtra',
    'getCharSequenceArrayListExtra', 'getCharSequenceExtra', 'getIntegerArrayListExtra',
    'getLongArrayExtra', 'getLongExtra', 'getParcelableArrayExtra', 'getParcelableArrayListExtra',
    'getParcelableExtra', 'getSerializableExtra', 'getShortArrayExtra', 'getShortExtra',
    'getStringArrayExtra', 'getStringArrayListExtra', 'getString', 'getInt',
    'getData', 'getDataString', 'getAction', 'getType', 'getScheme'
]

# System-protected broadcasts that can only be sent by system apps
PROTECTED_BROADCASTS = frozenset([
    'android.intent.action.SCREEN_OFF', 'android.intent.action.SCREEN_ON',
    'android.intent.action.USER_PRESENT', 'android.intent.action.TIME_TICK',
    'android.intent.action.TIMEZONE_CHANGED', 'android.intent.action.BOOT_COMPLETED',
    'android.intent.action.PACKAGE_INSTALL', 'android.intent.action.PACKAGE_ADDED',
    'android.intent.action.PACKAGE_REPLACED', 'android.intent.action.MY_PACKAGE_REPLACED',
    'android.intent.action.PACKAGE_REMOVED', 'android.intent.action.PACKAGE_FULLY_REMOVED',
    'android.intent.action.PACKAGE_CHANGED', 'android.intent.action.PACKAGE_RESTARTED',
    'android.intent.action.PACKAGE_DATA_CLEARED', 'android.intent.action.PACKAGE_FIRST_LAUNCH',
    'android.intent.action.BATTERY_CHANGED', 'android.intent.action.BATTERY_LOW',
    'android.intent.action.BATTERY_OKAY', 'android.intent.action.ACTION_POWER_CONNECTED',
    'android.intent.action.ACTION_POWER_DISCONNECTED', 'android.intent.action.ACTION_SHUTDOWN',
    'android.intent.action.DEVICE_STORAGE_LOW', 'android.intent.action.DEVICE_STORAGE_OK',
    'android.net.conn.CONNECTIVITY_CHANGE', 'android.net.wifi.WIFI_STATE_CHANGED',
    'android.net.wifi.SCAN_RESULTS', 'android.bluetooth.adapter.action.STATE_CHANGED',
    'android.intent.action.SIM_STATE_CHANGED', 'android.intent.action.AIRPLANE_MODE'
])

# Issue descriptions with improved formatting and actionable guidance
EXPORTED_WITH_PERMISSION_DESC = (
    "Component '{tag_name}' ({tag}) is exported and protected by a permission. However, "
    "permissions can be obtained by malicious apps installed prior to this one on Android < 5.0. "
    "Recommendation: Review the component for input validation and consider restricting access further. "
    "Reference: MSTG-PLATFORM-5"
)

EXPORTED_PROTECTED_BROADCAST_DESC = (
    "Component '{tag_name}' ({tag}) is exported and receives system-protected broadcasts. "
    "While these intents can only be sent by system apps, the component may still be vulnerable "
    "to second-order injection if it processes untrusted data. "
    "Recommendation: Validate all input data even from system sources."
)

EXPORTED_UNPROTECTED_DESC = (
    "Component '{tag_name}' ({tag}) is exported without permission protection, making it "
    "accessible by any app on the device. This exposes the component to potential intent injection, "
    "data leakage, or unauthorized access attacks. "
    "Recommendation: Add android:permission attribute or set android:exported='false' if external access is not required. "
    "Reference: MSTG-PLATFORM-5"
)

EXPORTED_TAGS_ISSUE_NAME = "Exported Components Without Adequate Protection"

class ComponentType(Enum):
    """Enum for different Android component types with metadata"""
    RECEIVER = ("receiver", "Broadcast Receiver", "exportedReceivers")
    PROVIDER = ("provider", "Content Provider", "exportedContentProviders") 
    ACTIVITY = ("activity", "Activity", "exportedActivities")
    SERVICE = ("service", "Service", "exportedServices")
    
    def __init__(self, tag_name: str, display_name: str, exploit_category: str):
        self.tag_name = tag_name
        self.display_name = display_name
        self.exploit_category = exploit_category

# Mapping from XML tag names to component types
TAG_TO_COMPONENT = {
    "receiver": ComponentType.RECEIVER,
    "provider": ComponentType.PROVIDER, 
    "activity": ComponentType.ACTIVITY,
    "activity-alias": ComponentType.ACTIVITY,  # Alias treated as activity
    "service": ComponentType.SERVICE
}

class ExportedTags(ManifestPlugin):
    """
    Plugin to detect exported Android components that lack adequate security protection.
    
    This plugin identifies components (activities, services, receivers, providers) that are
    exported and accessible by external applications, focusing on those without proper
    permission protection or input validation.
    """
    
    def __init__(self):
        super().__init__(category="manifest", name=EXPORTED_TAGS_ISSUE_NAME)
        self.vulnerable_components = ("activity", "activity-alias", "service", "receiver", "provider")
        self.all_files = None  # Set by framework for Java file analysis
        
    def run(self):
        """Main execution method that analyzes manifest and Java files"""
        try:
            log.debug("Starting exported components analysis")
            
            # Analyze each component type in the manifest
            for tag in self.vulnerable_components:
                components = self.manifest_xml.getElementsByTagName(tag)
                log.debug("Found %d %s components", len(components), tag)
                
                for component in components:
                    self._analyze_component_security(component, tag)
            
            # Enhance issues with Java code analysis if available
            if self.all_files:
                java_files = list(java_files_from_files(self.all_files))
                self._analyze_java_code_for_vulnerabilities(java_files)
            
            log.debug("Exported components analysis complete. Found %d issues.", len(self.issues))
        except Exception as e:
            log.exception("Error while analyzing exported components: %s", e)

    def _analyze_component_security(self, component_element, tag: str):
        """Analyze a single component for security issues"""
        try:
            component_name = component_element.attributes.get("android:name")
            if not component_name:
                log.debug("Component %s missing android:name attribute", tag)
                return
            component_name = component_name.value
        except AttributeError:
            log.debug("Unable to get name for %s component", tag)
            return
            
        # Determine if component is exported
        is_exported = self._is_component_exported(component_element, tag)
        if not is_exported:
            return
            
        # Check protection mechanisms
        has_permission = "android:permission" in component_element.attributes.keys()
        has_intent_filters = len(component_element.getElementsByTagName("intent-filter")) > 0
        
        component_type = TAG_TO_COMPONENT[tag]
        
        # Create base issue data
        issue_data = {
            "exported_enum": component_type,
            "tag_name": component_name,
            "package_name": self.package_name,
            "component_type": tag,
            "has_permission": has_permission,
            "has_intent_filters": has_intent_filters
        }
        
        # Analyze specific security scenarios
        if has_intent_filters:
            self._analyze_intent_filters(component_element, tag, component_name, 
                                       component_type, has_permission, issue_data)
        elif has_permission and self.min_sdk < 20:  # Pre-Android 5.0 permission issue
            self._create_issue(
                "Exported Component With Pre-5.0 Permission Vulnerability",
                Severity.INFO,
                EXPORTED_WITH_PERMISSION_DESC.format(tag=tag, tag_name=component_name),
                issue_data
            )
        elif not has_permission:  # Exported without any protection
            self._create_issue(
                EXPORTED_TAGS_ISSUE_NAME,
                Severity.WARNING,
                EXPORTED_UNPROTECTED_DESC.format(tag=tag, tag_name=component_name),
                issue_data
            )

    def _is_component_exported(self, component_element, tag: str) -> bool:
        """Determine if a component is exported based on manifest attributes and SDK version"""
        has_exported_attr = "android:exported" in component_element.attributes.keys()
        
        if has_exported_attr:
            exported_value = component_element.attributes.get("android:exported").value.lower()
            return exported_value == "true"
        
        # Special handling for content providers (exported by default pre-API 17)
        if tag == "provider":
            return self.min_sdk <= 16 or self.target_sdk <= 16
            
        # Components with intent-filters are exported by default (changed in Android 12)
        has_intent_filters = len(component_element.getElementsByTagName("intent-filter")) > 0
        if has_intent_filters:
            # Android 12+ requires explicit android:exported declaration
            if self.target_sdk >= 31:
                log.debug("Component %s has intent-filter but no explicit android:exported (required for API 31+)", tag)
            return True
            
        return False

    def _analyze_intent_filters(self, component_element, tag: str, component_name: str, 
                               component_type: ComponentType, has_permission: bool, issue_data: Dict):
        """Analyze intent filters for security implications"""
        intent_filters = component_element.getElementsByTagName("intent-filter")
        
        for intent_filter in intent_filters:
            actions = intent_filter.getElementsByTagName("action")
            
            for action in actions:
                try:
                    action_name = action.attributes["android:name"].value
                except KeyError:
                    log.debug("Action missing 'android:name' attribute")
                    continue
                
                # Check if this is a protected system broadcast
                is_protected = action_name in PROTECTED_BROADCASTS
                
                if is_protected:
                    self._create_issue(
                        "Exported Component Receiving Protected Broadcasts",
                        Severity.INFO,
                        EXPORTED_PROTECTED_BROADCAST_DESC.format(tag=tag, tag_name=component_name),
                        {**issue_data, "action_name": action_name, "is_protected_broadcast": True}
                    )
                elif has_permission and self.min_sdk < 20:
                    self._create_issue(
                        "Exported Component With Pre-5.0 Permission Vulnerability", 
                        Severity.INFO,
                        EXPORTED_WITH_PERMISSION_DESC.format(tag=tag, tag_name=component_name),
                        {**issue_data, "action_name": action_name}
                    )
                else:
                    self._create_issue(
                        EXPORTED_TAGS_ISSUE_NAME,
                        Severity.WARNING,
                        EXPORTED_UNPROTECTED_DESC.format(tag=tag, tag_name=component_name),
                        {**issue_data, "action_name": action_name}
                    )

    def _create_issue(self, name: str, severity: Severity, description: str, exploit_data: Dict):
        """Create and add a security issue"""
        issue = Issue(
            category="Manifest",
            name=name,
            severity=severity,
            description=description,
            file_object=self.manifest_path,
            apk_exploit_dict=exploit_data
        )
        self.issues.append(issue)

    def _analyze_java_code_for_vulnerabilities(self, java_files: List[str]):
        """Analyze Java source code to identify potential injection points"""
        try:
            log.debug("Analyzing %d Java files for exported component vulnerabilities", len(java_files))
            
            for issue in self.issues:
                if "tag_name" not in issue.apk_exploit_dict:
                    continue
                    
                # Convert package name to file path
                component_name = issue.apk_exploit_dict["tag_name"]
                file_path_component = component_name.replace(".", os.sep)
                
                self._extract_vulnerable_parameters(java_files, issue, file_path_component)
        except Exception as e:
            log.exception("Error while analyzing Java code for vulnerabilities: %s", e)

    def _extract_vulnerable_parameters(self, java_files: List[str], issue: Issue, search_name: str):
        """Extract parameters that could be injection points from Java code"""
        try:
            issue.apk_exploit_dict["vulnerable_parameters"] = []
            issue.apk_exploit_dict["entry_points"] = []
            
            for java_file in java_files:
                if search_name not in java_file:
                    continue
                    
                try:
                    with open(java_file, "r", encoding="utf-8") as f:
                        content = f.read()
                except (IOError, UnicodeDecodeError) as e:
                    log.debug("Failed to read %s: %s", java_file, e)
                    continue
                    
                try:
                    parsed_tree = javalang.parse.parse(content)
                except (javalang.parser.JavaSyntaxError, IndexError) as e:
                    log.debug("Failed to parse %s: %s", java_file, e)
                    continue
                
                component_type = issue.apk_exploit_dict.get("component_type", "")
                entry_methods = COMPONENT_ENTRIES.get(component_type, set())
                
                # Find entry point methods and extract potentially vulnerable parameters
                for _, method_decl in parsed_tree.filter(MethodDeclaration):
                    if method_decl.name in entry_methods:
                        issue.apk_exploit_dict["entry_points"].append(method_decl.name)
                        
                        # Look for intent/bundle data extraction calls
                        for _, method_call in parsed_tree.filter(MethodInvocation):
                            if method_call.member in EXTRAS_METHOD_NAMES and method_call.arguments:
                                for arg in method_call.arguments:
                                    if isinstance(arg, Literal) and arg.value:
                                        param_value = arg.value.strip('"\'')
                                        if param_value not in issue.apk_exploit_dict["vulnerable_parameters"]:
                                            issue.apk_exploit_dict["vulnerable_parameters"].append(param_value)
                
                # If we found parameters, we can stop searching other files
                if issue.apk_exploit_dict["vulnerable_parameters"]:
                    log.debug("Found %d parameters for %s", len(issue.apk_exploit_dict['vulnerable_parameters']), search_name)
                    break
        except Exception as e:
            log.exception("Error while extracting vulnerable parameters: %s", e)

# Plugin instance
plugin = ExportedTags()
