"""
Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
import logging
from proton.keyring_linux.core import KeyringBackendLinux

logger = logging.getLogger(__name__)


class LibsecretKeyringBackend(KeyringBackendLinux):
    """
    Libsecret backend using high-level password APIs (no explicit Service).
    https://gnome.pages.gitlab.gnome.org/libsecret/libsecret-python-examples.html
    """

    _secret_cache = None

    # We are using the same schema and application name
    # as the other keyring backend to be compatible
    SCHEMA = "org.freedesktop.Secret.Generic"
    APPLICATION_NAME = "Python keyring library"

    @classmethod
    def _get_priority(cls):
        return 4.0  # lower than secretservice

    @staticmethod
    def _import_secret():
        import gi  # pylint: disable=import-outside-toplevel,import-error
        gi.require_version('Secret', '1')
        from gi.repository import Secret  # pylint: disable=import-outside-toplevel,import-error
        return Secret

    @classmethod
    def _get_secret(cls):
        # The import is not top level because the app shouldn't crash
        # when the optional dependency is not available.
        # It's only imported the first time it's used and then cached
        if cls._secret_cache is None:
            cls._secret_cache = cls._import_secret()
        return cls._secret_cache

    @classmethod
    def _validate(cls):
        try:
            secret = cls._get_secret()
        except ValueError:
            logger.warning("Libsecret not available")
            return False
        test_schema = secret.Schema.new(
            "test",
            secret.SchemaFlags.NONE,
            {"key": secret.SchemaAttributeType.STRING}
        )
        secret.password_lookup_sync(test_schema, {"key": "test"}, None)
        logger.info("Using libsecret backend")
        return True

    def __init__(self):

        secret = self._get_secret()
        # These keys are used to find the keyring entry later.
        # They are being kept compatible with existing keys from secret service backend
        # so that the backends can be used interchangeably without losing user data.
        self.schema = secret.Schema.new(
            LibsecretKeyringBackend.SCHEMA,
            secret.SchemaFlags.NONE,  # pylint: disable=no-member
            {
                "application": secret.SchemaAttributeType.STRING,
                "service": secret.SchemaAttributeType.STRING,
                "username": secret.SchemaAttributeType.STRING
            }
        )

        super().__init__(self)

    def get_password(self, service_name, key):
        "Retrieve a password"
        secret = self._get_secret()
        result = secret.password_lookup_sync(
            self.schema,
            {
                "application": LibsecretKeyringBackend.APPLICATION_NAME,
                "service": service_name,
                "username": key
            },
            None
        )
        if result is None:
            return None
        return result

    def set_password(self, service_name, key, password):
        """Store a password"""
        secret = self._get_secret()
        secret.password_store_sync(
            self.schema,
            {
                "application": LibsecretKeyringBackend.APPLICATION_NAME,
                "service": service_name,
                "username": key
            },
            None,
            key,  # this is the title of the keyring entry
            password,
            None
        )

    def delete_password(self, service_name, key):
        """Delete a password"""
        secret = self._get_secret()
        secret.password_clear_sync(
            self.schema,
            {
                "application": LibsecretKeyringBackend.APPLICATION_NAME,
                "service": service_name,
                "username": key
            },
            None
        )
