import logging
from copy import deepcopy
from javalang.tree import MethodInvocation, MethodDeclaration, VariableDeclaration, Type, Literal
from qark.issue import Issue, Severity
from qark.plugins.helpers import valid_method_invocation, remove_dict_entry_by_value

log = logging.getLogger(__name__)

CATEGORY = "webview"
 
def valid_set_method_bool(method_invocation, str_bool, method_name="setAllowFileAccess"):
    """
    Checks if method_invocation is a call to `method_name` with a boolean argument of `str_bool`.

    :param method_invocation: The javalang MethodInvocation node.
    :param str_bool: Expected string boolean value ('true' or 'false').
    :param method_name: The method name to check.
    :return: True if matches, False otherwise.
    """
    if not method_invocation.arguments or not isinstance(method_invocation.arguments[0], Literal):
        return False
    return (valid_method_invocation(method_invocation, method_name, num_arguments=1) and
            method_invocation.arguments[0].value == str_bool)


def webview_default_vulnerable(tree, method_name, issue_name, description, file_object, severity=Severity.WARNING):
    """
    Analyzes Java AST to find WebViews where `method_name` was not explicitly called with false (insecure by default).

    :param tree: Parsed javalang AST tree.
    :param method_name: Name of the method to check (e.g. setAllowFileAccess).
    :param issue_name: Issue name for reporting.
    :param description: Description for the issue.
    :param file_object: Path of the file being analyzed.
    :param severity: Severity of the issue.
    :return: List of Issue objects.
    """
    issues = []
    for _, method_declaration in tree.filter(MethodDeclaration):
        webviews = {}
        webview_name = None

        for _, node in method_declaration:
            if ast_type_equals(node, VariableDeclaration):
                webview = node
                webviews = add_webview_to_dict(webviews, webview, "WebView")
                for name in [decl.name for decl in webview.declarators]:
                    log.debug("Discovered WebView variable '%s' at line %s", name, getattr(webview.position, 'line', '?'))

            elif ast_type_equals(node, MethodInvocation):
                method_invocation = node

                if method_invocation.member == "getSettings" and method_invocation.selectors:
                    webview_name = method_invocation.qualifier
                    for selector in method_invocation.selectors:
                        if valid_set_method_bool(selector, "false", method_name):
                            if webviews.get(webview_name):
                                log.debug("Secured webview '%s' via getSettings().%s(false)", webview_name, method_name)
                                webviews = remove_dict_entry_by_value(webviews, webview_name)

                elif (valid_set_method_bool(method_invocation, "false", method_name) and webviews.get(webview_name)):
                    log.debug("Secured webview '%s' via direct call to %s(false)", webview_name, method_name)
                    webviews = remove_dict_entry_by_value(webviews, webview_name)

        for webview in set(webviews.values()):
            log.debug("WebView '%s' remains vulnerable (missing %s=false)", webview, method_name)
            issues.append(Issue(
                category=CATEGORY,
                name=issue_name,
                severity=severity,
                description=description,
                line_number=webview.position,
                file_object=file_object
            ))

    return issues


def add_webview_to_dict(webviews, webview, java_type):
    """
    Adds a WebView variable declaration to the dictionary if it's of type `java_type`.

    :param webviews: Existing dictionary of webviews.
    :param webview: VariableDeclaration AST node.
    :param java_type: Expected Java type name (e.g. 'WebView').
    :return: Updated dictionary.
    """
    updated = deepcopy(webviews)
    if isinstance(webview.type, Type) and webview.type.name == java_type:
        for declarator in webview.declarators:
            updated[declarator.name] = webview
            log.debug("Added WebView variable '%s' to tracking dictionary", declarator.name)
    return updated


def ast_type_equals(node, pattern):
    """Helper to check AST node type."""
    return node == pattern or (isinstance(pattern, type) and isinstance(node, pattern))

