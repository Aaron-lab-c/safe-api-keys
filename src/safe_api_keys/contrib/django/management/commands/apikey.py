"""``python manage.py apikey issue|verify|revoke|rotate|list|purge`` using ``settings.SAFE_API_KEYS``."""

from __future__ import annotations

import argparse
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from safe_api_keys.cli import EXIT_OK, add_commands, execute
from safe_api_keys.contrib.django.conf import get_manager


class Command(BaseCommand):
    help = "Manage API keys (issue, verify, revoke, rotate, list, purge)."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="command", metavar="COMMAND")
        sub.required = True
        add_commands(sub, standalone=False)

    def handle(self, *args: Any, **options: Any) -> None:
        ns = argparse.Namespace(**options)
        if not hasattr(ns, "json"):
            ns.json = False
        rc = execute(ns, lambda _ns: get_manager(), self.stdout, self.stderr)
        if rc != EXIT_OK:
            raise CommandError(f"apikey {ns.command} failed (exit {rc})", returncode=rc)
