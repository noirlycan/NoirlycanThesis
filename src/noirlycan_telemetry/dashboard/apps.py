from django.apps import AppConfig


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "noirlycan_telemetry.dashboard"
    label = "noirlycan_dashboard"
    verbose_name = "Noirlycan Dashboard"
