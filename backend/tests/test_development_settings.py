from msap.settings import development as development_settings


def test_development_settings_include_local_origins():
    frontend_origins = {
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
    backend_origins = {
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    }

    assert frontend_origins <= set(development_settings.CSRF_TRUSTED_ORIGINS)
    assert backend_origins <= set(development_settings.CSRF_TRUSTED_ORIGINS)
    assert frontend_origins <= set(development_settings.CORS_ALLOWED_ORIGINS)
