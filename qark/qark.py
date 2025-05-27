import logging
import logging.config
import os
import click

from qark.utils import environ_path_variable_exists

DEBUG_LOG_PATH = os.path.join(os.getcwd(), "qark_debug.log")

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
	Jineen Abu Amr  . 
	Daoud Abu Madi  · 
	3asem Alselwady · 
	R7mah Alqur3an  · 
"""
    click.secho(banner, fg="bright_blue", bold=True)

@click.command()
@click.option("--analyze", "analyze_mode", is_flag=True, help="Run only static analysis.")
@click.option("--build-path", type=click.Path(resolve_path=True, file_okay=False),
              help="Path to place decompiled files.")
@click.option("--debug/--no-debug", default=False, help="Show debugging statements.", show_default=True)
@click.option("--sdk-path", type=click.Path(exists=True, file_okay=False, resolve_path=True),              
              help="Path to the SDK directory (required for static analysis or exploit APK if needed).")
@click.option("--exploit-apk/--no-exploit-apk", default=False,
              help="Create an exploit APK targeting vulnerabilities. Default is 'no-exploit-apk'.", show_default=True)
@click.option("--report-type", type=click.Choice(["html", "xml", "json", "csv"]), default="html",
              help="Type of report to generate.", show_default=True)
@click.option("--report-path", type=click.Path(resolve_path=True, file_okay=False), default=None,
              help="Directory to save the generated report.")
@click.version_option("5")
@click.pass_context

def cli(ctx, analyze_mode, sdk_path, build_path, exploit_apk, debug, report_type, report_path):
    print_banner()

    if not analyze_mode:
        click.secho("⚠️  Please specify --help to show all options.", fg="red", bold=True)
        return

    if analyze_mode:
        input_type = click.prompt("🖋️  What type of input do you want to analyze?", type=click.Choice(['apk', 'java'], case_sensitive=False))
        source = click.prompt(f"🖋️  Enter the path to your {input_type} file", type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=True))

        if build_path is None:
            base_name = os.path.splitext(os.path.basename(source))[0]
            build_path = os.path.join(os.getcwd(), f"build_{base_name}")

        from qark.decompiler.decompiler import Decompiler
        level = "DEBUG" if debug else "INFO"
        initialize_logging(level)

        click.secho(f"🔧 Decompiling APK/source code into: {build_path}", fg="yellow")
        decompiler = Decompiler(path_to_source=source, build_directory=build_path)
        decompiler.run()

        from qark.scanner.scanner import Scanner
        click.secho("🔍 Running static analysis...", fg="yellow")

        path_to_source = (
            decompiler.path_to_source
            if decompiler.source_code else
            decompiler.decompiled_java_path
        )

        click.secho(f"📂 Decompiled Java code path: {decompiler.decompiled_java_path}", fg="cyan")
        click.secho(f"🛠️ Decompiler used: {decompiler.decompiler_used}", fg="cyan")

        scanner = Scanner(
            manifest_path=decompiler.manifest_path,
            path_to_source=path_to_source
        )
        scanner.run()
        click.secho("✅ Static analysis completed.", fg="green")

        from qark.report import Report
        click.secho("📝 Generating report...", fg="yellow")
        report = Report(issues=set(scanner.issues), report_path=report_path)
        report_path_final = report.generate(file_type=report_type)
        click.secho(f"📁 Report saved to: {report_path_final}", fg="green")

        if exploit_apk:
            if not sdk_path:
                if environ_path_variable_exists("ANDROID_SDK_HOME"):
                    sdk_path = os.environ["ANDROID_SDK_HOME"]
                elif environ_path_variable_exists("ANDROID_HOME"):
                    sdk_path = os.environ["ANDROID_HOME"]
                elif environ_path_variable_exists("ANDROID_SDK_ROOT"):
                    sdk_path = os.environ["ANDROID_SDK_ROOT"]
                else:
                    click.secho("❌ Please provide --sdk-path or set ANDROID_SDK_* env vars for exploit APK.", fg="red")
                    return

            from qark.apk_builder import APKBuilder
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

if __name__ == "__main__":
    cli()

