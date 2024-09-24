"""
Module for all linux keyring backends.


The public interface and the functionality that's common to all supported
VPN connection backends is defined in this module.


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
from proton.keyring._base import Keyring
from proton.keyring.exceptions import KeyringLocked, KeyringError

logger = logging.getLogger(__name__)


class KeyringBackendLinux(Keyring):  # pylint: disable=too-few-public-methods
    """Keyring linux backend.

    All backend implementations should derive from this class, so methods
    can be reused, unless there are backend specific approaches.
    """
    KEYRING_SERVICE = "Proton"

    def __init__(self, keyring_backend):
        super().__init__()
        self.__keyring_backend = keyring_backend

    # pylint: disable=duplicate-code
    def _get_item(self, key):
        try:
            stored_data = self.__keyring_backend.get_password(  # pylint: disable=duplicate-code
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
        except json.JSONDecodeError as excp:
            # Delete data (it's invalid anyway)
            self._del_item(key)
            raise KeyError(key) from excp

    def _del_item(self, key):
        try:
            self.__keyring_backend.delete_password(self.KEYRING_SERVICE, key)
        except keyring.errors.PasswordDeleteError as excp:
            logging.exception("Unable to delete entry from keyring")
            raise KeyError(key) from excp
        except keyring.errors.KeyringError as excp:
            logging.exception("Keyring error while deleting")
            raise KeyringError(excp) from excp

    def _set_item(self, key, value):
        json_data = json.dumps(value)
        try:
            self.__keyring_backend.set_password(
                self.KEYRING_SERVICE,
                key,
                json_data
            )
        except keyring.errors.PasswordSetError as excp:
            logging.info("Unable to set value to keyring")
            raise KeyError(excp) from excp
        except keyring.errors.KeyringError as excp:
            logging.exception("Keyring error while setting")
            raise KeyringError(excp) from excp

    @classmethod
    def _is_backend_working(cls, keyring_backend):
        """Check that a backend is working properly.

        It can happen so that a backend is installed but it might be
        misconfigured. But adding this test, we can asses if the backend
        is working correctly or not. If not then another backend should be tried instead.

        keyring.errors.InitError will be thrown if the backend system can not be initialized,
        indicating that possibly it might be misconfigured.
        """
        try:
            keyring_backend.get_password(
                "ProtonVPN",
                "TestingThatBackendIsWorking"
            )
            return True
        except (
            keyring.errors.InitError, keyring.errors.KeyringLocked,
            keyring.errors.NoKeyringError
        ):
            logger.exception("Keyring %s error", keyring_backend)
            return False
