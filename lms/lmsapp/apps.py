from django.apps import AppConfig

class LmsappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'lmsapp'

    def ready(self):
        import lmsapp.signals  # Import signals to connect
