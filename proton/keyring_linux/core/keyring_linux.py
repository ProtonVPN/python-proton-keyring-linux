import json

import keyring
from proton.keyring._base import Keyring
from proton.keyring.exceptions import KeyringNotWorking
import logging

logger = logging.getLogger(__name__)


class KeyringBackendLinux(Keyring):
    __keyring_service = "Proton"

    def __init__(self, keyring_backend):
        super().__init__()
        self.__keyring_backend = keyring_backend

    def _get_item(self, key):
        try:
            stored_data = self.__keyring_backend.get_password(
                self.__keyring_service,
                key
            )
        except keyring.errors.KeyringError as e:
            raise KeyringNotWorking(e) from e

        # Since we're borrowing the dict interface,
        # be consistent and throw a KeyError if it doesn't exist
        if stored_data is None:
            raise KeyError(key)

        try:
            return json.loads(stored_data)
        except json.JSONDecodeError as e:
            # Delete data (it's invalid anyway)
            self._del_item(key)
            raise KeyError(key) from e

    def _del_item(self, key):
        try:
            self.__keyring_backend.delete_password(self.__keyring_service, key)
        except keyring.errors.PasswordDeleteError as e:
            raise KeyError(key) from e
        except keyring.errors.KeyringError as e:
            raise KeyringNotWorking(e) from e

    def _set_item(self, key, value):
        json_data = json.dumps(value)
        try:
            self.__keyring_backend.set_password(
                self.__keyring_service,
                key,
                json_data
            )
        except keyring.errors.PasswordSetError as e:
            raise KeyError(e)
        except keyring.errors.KeyringError as e:
            raise KeyringNotWorking(e) from e

    @classmethod
    def _is_backend_working(self, keyring_backend):
        """Check that a backend is working properly.

        It can happen so that a backend is installed but it might be
        missonfigured. But adding this test, we can asses if the backend
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
            logger.exception(f"Keyring \"{keyring_backend}\" error")
            return False
        except Exception as e: # noqa
            logger.exception(f"Unexpected keyring \"{keyring_backend}\" error")
            return False
