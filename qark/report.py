from os import path
import os
from datetime import datetime

from jinja2 import Environment, PackageLoader, select_autoescape, Template

from qark.issue import (Issue, Severity, issue_json)
from qark.utils import create_directories_to_path

import logging

# تحديد المسار للتقرير - يعمل على Windows و Linux
# البحث عن مجلد Qark5 في Desktop للمستخدم الحالي
user_home = os.path.expanduser("~")
desktop_path = os.path.join(user_home, "OneDrive", "Desktop")  # Windows
if not os.path.exists(desktop_path):
    desktop_path = os.path.join(user_home, "Desktop")  # Linux/Mac

DEFAULT_REPORT_PATH = os.path.join(desktop_path, "Qark5", "qark", "report")
 
jinja_env = Environment(
    loader=PackageLoader('qark', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

jinja_env.filters['issue_json'] = issue_json

class Report(object):
    """An object to store issues against and to generate reports in different formats."""

    __instance = None

    def __new__(cls, issues=None, report_path=None, keep_report=False):
        if Report.__instance is None:
            Report.__instance = object.__new__(cls)
        return Report.__instance

    def __init__(self, issues=None, report_path=None, keep_report=False):
        self.issues = issues if issues else []
        self.report_path = report_path or DEFAULT_REPORT_PATH
        self.keep_report = keep_report

    def generate(self, file_type='html', template_file=None):
        create_directories_to_path(self.report_path)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        full_report_path = path.join(self.report_path, f'report_{timestamp}.{file_type}')

        if not template_file:
            template = jinja_env.get_template(f'{file_type}_report.jinja')
        else:
            template = Template(template_file)

        # ✅ Sort by custom priority
        priority_order = {
            Severity.VULNERABILITY: 1,
            Severity.WARNING: 2,
            Severity.ERROR: 3,
            Severity.INFO: 4
        }

        sorted_issues = sorted(self.issues, key=lambda issue: priority_order.get(issue.severity, 5))

        # 🗑️ تم إزالة دعم PDF، فقط تنسيقات النص العادية مدعومة
        with open(full_report_path, mode='w', encoding="utf-8") as report_file:
            stream = template.stream(issues=sorted_issues)
            stream.enable_buffering(5)
            stream.dump(report_file)
            report_file.write('\n')

        return full_report_path