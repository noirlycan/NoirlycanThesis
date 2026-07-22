from __future__ import annotations

from django.utils.translation import gettext_lazy as _

from jet.dashboard import modules
from jet.dashboard.dashboard import Dashboard


class NoirlycanIndexDashboard(Dashboard):
    columns = 3

    def init_with_context(self, context) -> None:
        self.available_children.append(modules.LinkList)
        self.children.append(
            modules.LinkList(
                _("Telemetry"),
                children=[
                    {
                        "title": _("Live dashboard"),
                        "url": "/",
                        "external": False,
                    },
                    {
                        "title": _("API health"),
                        "url": "/api/health",
                        "external": False,
                    },
                    {
                        "title": _("Classifier rules"),
                        "url": "/#tab=rules",
                        "external": False,
                    },
                ],
                column=0,
                order=0,
            )
        )
        self.children.append(
            modules.LinkList(
                _("Operations"),
                children=[
                    {
                        "title": _("Upload samples"),
                        "url": "/#tab=upload",
                        "external": False,
                    },
                    {
                        "title": _("Session logs"),
                        "url": "/#tab=sessions",
                        "external": False,
                    },
                    {
                        "title": _("Runtime settings"),
                        "url": "/api/runtime",
                        "external": False,
                    },
                ],
                column=1,
                order=0,
            )
        )
