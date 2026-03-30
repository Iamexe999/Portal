"""
Console UI with colored output and progress steps.
"""

import sys
import os

# ANSI color support
USE_COLOR = sys.stdout.isatty() and os.name != "nt" or \
    (os.name == "nt" and os.environ.get("WT_SESSION"))  # Windows Terminal

RESET  = "\033[0m"  if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
GREEN  = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED    = "\033[91m" if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
DIM    = "\033[2m"  if USE_COLOR else ""

BANNER = f"""\
{BOLD}{CYAN}
  ╔═══════════════════════════════════════════╗
  ║   ██████╗  ██████╗ ██████╗ ████████╗     ║
  ║   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝     ║
  ║   ██████╔╝██║   ██║██████╔╝   ██║        ║
  ║   ██╔═══╝ ██║   ██║██╔══██╗   ██║        ║
  ║   ██║     ╚██████╔╝██║  ██║   ██║        ║
  ║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝        ║
  ║       A B L I Z E R                      ║
  ║   Make any .exe portable. No admin.      ║
  ╚═══════════════════════════════════════════╝
{RESET}"""

STEP_NUM = [0]


class ConsoleUI:

    def print_banner(self):
        print(BANNER)

    def step(self, message: str):
        STEP_NUM[0] += 1
        n = STEP_NUM[0]
        print(f"\n{BOLD}{CYAN}[{n}]{RESET} {BOLD}{message}...{RESET}")

    def info(self, message: str):
        print(f"    {DIM}→{RESET} {message}")

    def success(self, message: str):
        print(f"\n{GREEN}{BOLD}✔ {message}{RESET}")

    def warn(self, message: str):
        print(f"{YELLOW}  {message}{RESET}")

    def error(self, message: str):
        print(f"{RED}{BOLD}✘ {message}{RESET}", file=sys.stderr)
