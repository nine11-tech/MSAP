from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from apps.api.permissions import IsMSAPAdmin


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("apps.api.urls")),
]

if settings.DEBUG:
    urlpatterns += [
        path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
        path(
            "api/docs/",
            SpectacularSwaggerView.as_view(url_name="schema"),
            name="swagger-ui",
        ),
    ]
else:
    urlpatterns += [
        path(
            "api/schema/",
            SpectacularAPIView.as_view(permission_classes=[IsMSAPAdmin]),
            name="schema",
        ),
        path(
            "api/docs/",
            SpectacularSwaggerView.as_view(
                url_name="schema",
                permission_classes=[IsMSAPAdmin],
            ),
            name="swagger-ui",
        ),
    ]
