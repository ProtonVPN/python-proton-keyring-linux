"""Module for Linux Secret Service Keyring backend.


Copyright (c) 2023 Proton AG

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
import json

import logging
import keyring
from proton.keyring.exceptions import KeyringLocked, KeyringError
from proton.keyring_linux.core import KeyringBackendLinux

logger = logging.getLogger(__name__)


# pylint: disable=too-few-public-methods
class KeyringBackendLinuxSecretService(KeyringBackendLinux):
    """Implements the Secret Service keyring backend."""
    @classmethod
    def _get_priority(cls):
        return 5.

    @classmethod
    def _validate(cls):
        try:
            # pylint: disable=import-outside-toplevel
            from keyring.backends import SecretService
            return cls._is_backend_working(SecretService.Keyring())
        except ModuleNotFoundError:
            logger.debug("Gnome-Keyring module not found")
            return False

    def __init__(self):
        # pylint: disable=import-outside-toplevel
        from keyring.backends import SecretService
        self._backend = SecretService.Keyring()
        super().__init__(self._backend)

    def _get_item(self, key):
        try:
            stored_data = self._backend.get_password(
                self.KEYRING_SERVICE,
                key
            )
        except keyring.errors.KeyringLocked as excp:
            logging.info("Keyring locked while getting")
            raise KeyringLocked("Keyring is locked") from excp
        except keyring.errors.KeyringError as excp:
            logging.exception("Keyring error while getting")
            raise KeyringError(excp) from excp

        # Since we're borrowing the dict interface,
        # be consistent and throw a KeyError if it doesn't exist
        if stored_data is None:
            raise KeyError(key)

        try:
            return json.loads(stored_data)
        except json.JSONDecodeError:
            # gnome-keyring has a bug when processing new lines.
            # Anytime we store the data to the keyring, we store all newlines in
            # escaped form, aka \\n. For some reason, when gnome-keyring has no password
            # set, upon reading from the keyring it seems auto-escape the string and the
            # output becomes \n thus, treating this as a literal new line character,
            # causing a crash when we try to load the string via json, because again, \n are
            # treated literally. On the contrary, when the keyring has a password set,
            # and when we retrieve the data from the keyring, the new lines are properly
            # escaped and thus it does not crash once we try to load the string to json format.
            # From out testing, both via secret-storage and libsecret packages
            # (and even secret-tool) we were able to recreate this issue, thus indicating that
            # the issue is with gnome-keyring and not related to packages that
            # communicate with the gnome-keyring.
            # See more at:
            # https://discourse.gnome.org/t/possible-bug-or-feature-storing-getting-data-keyring-protected-vs-unprotected-keyring/20312

            # This fixed was found by Wizzerinus on GitHub and a PR was create by Anonymous941
            # https://github.com/ProtonVPN/python-proton-keyring-linux/pull/1

            stored_data = stored_data.replace("\n", "\\n")

        try:
            return json.loads(stored_data)
        except json.JSONDecodeError as excp:
            # Something is wrong here, delete data (it's invalid anyway)
            logging.exception("Keyring credential is not valid JSON, deleting")
            self._del_item(key)
            raise KeyError(key) from excp
