from rest_framework import serializers

from drf_spectacular.drainage import warn
from drf_spectacular.extensions import OpenApiAuthenticationExtension, OpenApiViewExtension
from drf_spectacular.utils import extend_schema


class SimpleJWTScheme(OpenApiAuthenticationExtension):
    target_class = 'rest_framework_simplejwt.authentication.JWTAuthentication'
    name = 'jwtAuth'

    def get_security_definition(self, auto_schema):
        from rest_framework_simplejwt.settings import api_settings

        if len(api_settings.AUTH_HEADER_TYPES) > 1:
            warn(
                f'OpenAPI3 can only have one "bearerFormat". JWT Settings specify '
                f'{api_settings.AUTH_HEADER_TYPES}. Using the first one.'
            )
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': api_settings.AUTH_HEADER_TYPES[0],
        }


class SimpleJWTTokenRefreshView(OpenApiViewExtension):
    target_class = 'rest_framework_simplejwt.views.TokenRefreshView'

    def view_replacement(self):
        class TokenRefreshResponseSerializer(serializers.Serializer):
            access = serializers.CharField()

        class Fixed(self.target_class):
            @extend_schema(responses=TokenRefreshResponseSerializer)
            def post(self, request, *args, **kwargs):
                pass  # pragma: no cover

        return Fixed


class SimpleJWTTokenObtainPairView(OpenApiViewExtension):
    target_class = 'rest_framework_simplejwt.views.TokenObtainPairView'

    def view_replacement(self):
        class TokenObtainPairResponseSerializer(serializers.Serializer):
            access = serializers.CharField()
            refresh = serializers.CharField()

        class Fixed(self.target_class):
            @extend_schema(responses=TokenObtainPairResponseSerializer)
            def post(self, request, *args, **kwargs):
                pass  # pragma: no cover

        return Fixed
