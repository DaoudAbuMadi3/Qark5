from os import path
from datetime import datetime  # إضافة استيراد datetime لتوليد طابع زمني

from jinja2 import Environment, PackageLoader, select_autoescape, Template

from issue import (Issue, Severity, issue_json)  # noqa:F401 These are expected to be used later.
from utils import create_directories_to_path

DEFAULT_REPORT_PATH = path.join(path.dirname(path.realpath(__file__)), 'report', '')

jinja_env = Environment(
    loader=PackageLoader('qark', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

jinja_env.filters['issue_json'] = issue_json

class Report(object):
    """An object to store issues against and to generate reports in different formats.

    There is one instance created per QARK run and it uses a classic Singleton pattern
    to make it easy to get a reference to that instance anywhere in QARK.
    """

    __instance = None

    def __new__(cls, issues=None, report_path=None, keep_report=False):
        if Report.__instance is None:
            Report.__instance = object.__new__(cls)

        return Report.__instance

    def __init__(self, issues=None, report_path=None, keep_report=False):
        """Initialize the report."""
        self.issues = issues if issues else []
        self.report_path = report_path or DEFAULT_REPORT_PATH
        self.keep_report = keep_report

    def generate(self, file_type='html', template_file=None):
        """Generate report using Jinja2 streaming for better performance."""
        create_directories_to_path(self.report_path)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        full_report_path = path.join(self.report_path, f'report_{timestamp}.{file_type}')

        if not template_file:
            template = jinja_env.get_template(f'{file_type}_report.jinja')
        else:
            template = Template(template_file)

        with open(full_report_path, mode='w', encoding="utf-8") as report_file:
            stream = template.stream(issues=list(self.issues))
            stream.enable_buffering(5)  # 🔥 يرندر كل 5 مشاكل مع بعض بدل الكل
            stream.dump(report_file)
            report_file.write('\n')

        return full_report_path
