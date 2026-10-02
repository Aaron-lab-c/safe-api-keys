#!/usr/bin/env python
"""Django's command-line utility for the safe-api-keys example project."""
import os
import sys
from pathlib import Path


def main():
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here.parent))  # makes the `django_app` settings package importable
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_app.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
