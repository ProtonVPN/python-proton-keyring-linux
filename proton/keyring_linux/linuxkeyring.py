import json
from proton.keyring._base import KeyringBackend, KeyringNotWorking
import os


class KeyringBackendLinux(KeyringBackend):
    __keyring_service = 'Proton'

    @classmethod
    def _get_priority(cls) -> int:
        # Make sure this is not instantiable if not explicitely overriden
        return None

    def __init__(self, keyring_backend):
        self.__keyring_backend = keyring_backend

    def __getitem__(self, key):
        self._ensure_key_is_valid(key)

        try:
            stored_data = self.__keyring_backend.get_password(
                self.__keyring_service,
                key
            )
        except Exception as e:
            raise KeyError(key)

        # Since we're borrowing the dict interface,
        # be consistent and throw a KeyError if it doesn't exist
        if stored_data is None:
            raise KeyError(key)

        try:
            return json.loads(stored_data)
        except Exception as e:
            #FIXME: log maybe
            # Delete data (it's invalid anyway)
            del self[key]
            raise KeyError(key)

    def __delitem__(self, key):
        import keyring

        self._ensure_key_is_valid(key)

        try:
            self.__keyring_backend.delete_password(self.__keyring_service, key)
        except keyring.errors.PasswordDeleteError as e:
            raise KeyError(key)
        except Exception as e:
            #FIXME: log
            raise KeyringNotWorking()

    def __setitem__(self, key, value):
        self._ensure_key_is_valid(key)
        self._ensure_value_is_valid(value)

        json_data = json.dumps(value)
        try:
            self.__keyring_backend.set_password(
                self.__keyring_service,
                key,
                json_data
            )
        except Exception as e:
            #FIXME: log
            raise KeyringNotWorking()

    @classmethod
    def _is_backend_working(self , keyring_backend):
        """Check that a backend is working properly.

        It can happen so that a backend is installed but it might be
        missonfigured. But adding this test, we can asses if the backend
        is working correctly or not. If not then another backend should be tried instead.

        keyring.errors.InitError will be thrown if the backend system can not be initialized,
        indicating that possibly it might be misconfigured.
        """
        import keyring
        try:
            keyring_backend.get_password(
                "ProtonVPN",
                "TestingThatBackendIsWorking"
            )
            return True
        except (keyring.errors.InitError) as e:
            return False
        except: # noqa
            #FIXME: we might want to log that
            return False


class KeyringBackendLinuxKwallet(KeyringBackendLinux):
    @classmethod
    def _get_priority(cls):
        # We want to have more priority if we're using KDE, otherwise slightly less
        
        if 'KDE' in os.getenv('XDG_CURRENT_DESKTOP', '').split(":"):
            return 5.1
        
        return 4.9

    @classmethod
    def _validate(cls):
        from keyring.backends import kwallet
        return cls._is_backend_working(kwallet.DBusKeyring())

    def __init__(self):
        from keyring.backends import kwallet
        super().__init__(kwallet.DBusKeyring())

class KeyringBackendLinuxSecretService(KeyringBackendLinux):
    @classmethod
    def _get_priority(cls):
        return 5.

    @classmethod
    def _validate(cls):
        from keyring.backends import SecretService
        return cls._is_backend_working(SecretService.Keyring())

    def __init__(self):
        from keyring.backends import SecretService
        super().__init__(SecretService.Keyring())
