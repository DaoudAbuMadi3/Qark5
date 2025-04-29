#!/usr/bin/env python3

from __future__ import absolute_import
import logging
import logging.config
import os
import click

from utils import environ_path_variable_exists

DEBUG_LOG_PATH = os.path.join(os.getcwd(), "qark_debug.log")

# Environment variable names for the SDK
ANDROID_SDK_HOME = "ANDROID_SDK_HOME"
ANDROID_HOME = "ANDROID_HOME"
ANDROID_SDK_ROOT = "ANDROID_SDK_ROOT"

logger = logging.getLogger(__name__)
QARK_VERSION = "5"

def print_banner():
    banner = r"""
 .d88888b.         d8888 8888888b.  888    d8P  
d88P" "Y88b       d88888 888   Y88b 888   d8P   
888     888      d88P888 888    888 888  d8P    
888     888     d88P 888 888   d88P 888d88K     
888     888    d88P  888 8888888P"  8888888b    
888 Y8b 888   d88P   888 888 T88b   888  Y88b   
Y88b.Y8b88P  d8888888888 888  T88b  888   Y88b  
 "Y888888"  d88P     888 888   T88b 888    Y88b 
       Y8b                                      

        🔍 Quick Android Review Kit version-5
Developed by
	3asem Alselwady . 
	Jineen Abu Amr  · 
	Daoud Abu Madi  · 
	R7mah Alqur3an  · 
"""
    click.secho(banner, fg="bright_blue", bold=True)


@click.command()
@click.option("--sdk-path", type=click.Path(exists=True, file_okay=False, resolve_path=True),
              help="Path to the downloaded SDK directory if already downloaded. "
                   "Only necessary if --exploit-apk is passed. If not passed, QARK "
                   "will use ANDROID_SDK_HOME / ANDROID_HOME / ANDROID_SDK_ROOT.",
              show_default=True)
@click.option("--build-path", type=click.Path(resolve_path=True, file_okay=False),
              help="Path to place decompiled files and exploit APK.", default="build", show_default=True)
@click.option("--debug/--no-debug", default=False, help="Show debugging statements (helpful for issues).",
              show_default=True)
@click.option("--apk", "source", help="APK to decompile and run static analysis. If passed, the --java option is not used.",
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=True))
@click.option("--java", "source", type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=True),
              help="A directory containing Java code, or a Java file, to run static analysis. If passed, the --apk option is not used.")
@click.option("--report-type", type=click.Choice(["html", "xml", "json", "csv"]),
              help="Type of report to generate along with terminal output. Default is HTML.",
              default="html", show_default=True)
@click.option("--exploit-apk/--no-exploit-apk", default=False,
              help="Create an exploit APK targeting a few vulnerabilities. Default is 'no-exploit-apk'.", show_default=True)
@click.option("--report-path", type=click.Path(resolve_path=True, file_okay=False), default=None,
              help="Report output path. Default is current directory.", show_default=True)
@click.option("--keep-report/--no-keep-report", default=False,
              help="Append to final report file. Default is 'no-keep-report'.", show_default=True)
@click.version_option("5")
@click.pass_context
def cli(ctx, sdk_path, build_path, debug, source, report_type, exploit_apk, report_path, keep_report):
    print_banner()

    if not source:
        click.secho("⚠️  Please pass a source for scanning through either --java or --apk\n", fg="red", bold=True)

        click.secho("📘 Usage examples:", fg="blue", bold=True)
        click.secho("  ▶ python3 qark.py --apk myApp.apk", fg="green")
        click.secho("  ▶ python3 qark.py --java /path/to/java/code", fg="green")

        click.secho("\n📌 Main options:", fg="blue", bold=True)
        click.secho("  --apk PATH             APK file for analysis", fg="cyan")
        click.secho("  --java PATH            Java code folder or file", fg="cyan")
        click.secho("  --report-type TYPE     Report format: html | xml | json | csv", fg="cyan")
        click.secho("  --exploit-apk          Create exploit APK if vulnerable", fg="cyan")
        click.secho("  --debug                Enable verbose debug output", fg="cyan")
        click.secho("  --sdk-path             Android SDK path", fg="cyan")
        return

    if exploit_apk and not sdk_path:
        if environ_path_variable_exists(ANDROID_SDK_HOME):
            sdk_path = os.environ[ANDROID_SDK_HOME]
        elif environ_path_variable_exists(ANDROID_HOME):
            sdk_path = os.environ[ANDROID_HOME]
        elif environ_path_variable_exists(ANDROID_SDK_ROOT):
            sdk_path = os.environ[ANDROID_SDK_ROOT]
        else:
            click.secho("❌ Please provide path to Android SDK for exploit APK building.", fg="red")
            return

    from decompiler.decompiler import Decompiler
    level = "DEBUG" if debug else "INFO"
    initialize_logging(level)

    click.secho("🔧 Decompiling APK/source code...", fg="yellow")
    decompiler = Decompiler(path_to_source=source, build_directory=build_path)
    decompiler.run()

    from scanner.scanner import Scanner
    click.secho("🔍 Running security scans...", fg="yellow")
    path_to_source = decompiler.path_to_source if decompiler.source_code else decompiler.build_directory
    scanner = Scanner(manifest_path=decompiler.manifest_path, path_to_source=path_to_source)
    scanner.run()
    click.secho("✅ Scans completed.", fg="green")

    from report import Report
    click.secho("📝 Generating report...", fg="yellow")
    report = Report(issues=set(scanner.issues), report_path=report_path, keep_report=keep_report)
    report_path = report.generate(file_type=report_type)
    click.secho(f"📁 Report saved to: {report_path}", fg="green")

    if exploit_apk:
        from apk_builder import APKBuilder
        click.secho("🛠️  Building exploit APK...", fg="yellow")
        exploit_builder = APKBuilder(
            exploit_apk_path=build_path,
            issues=scanner.issues,
            apk_name=decompiler.apk_name,
            manifest_path=decompiler.manifest_path,
            sdk_path=sdk_path
        )
        exploit_builder.build()
        click.secho("✅ Exploit APK built successfully!", fg="green")


def initialize_logging(level):
    handlers = {
        "stderr_handler": {
            "level": level,
            "class": "logging.StreamHandler"
        }
    }
    loggers = ["stderr_handler"]

    if level == "DEBUG":
        handlers["debug_handler"] = {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "filename": DEBUG_LOG_PATH,
            "mode": "w",
            "formatter": "standard"
        }
        loggers.append("debug_handler")

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            }
        },
        "handlers": handlers,
        "loggers": {
            "": {
                "handlers": loggers,
                "level": level,
                "propagate": True
            }
        }
    })

    if level == "DEBUG":
        logger.debug("Debug logging enabled")


# ✅ Entry point
if __name__ == "__main__":
    cli()
