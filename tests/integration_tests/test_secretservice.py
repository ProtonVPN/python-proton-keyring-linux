from proton.keyring_linux.linuxkeyring import KeyringBackendLinuxSecretService
import pytest
from unittest import mock
from keyring.backends import SecretService


TEST_SERVICE = "TestProton"
TEST_KEY = "test-key"


@pytest.fixture
def cleanup_env():
    ss = SecretService.Keyring()
    try:
        ss.delete_password(TEST_SERVICE, TEST_KEY)
    except: # noqa
        pass


class TestInegrationSecretService:
    def setup_module(self):
        cleanup_env()

    def teardown_module(self):
        cleanup_env()

    @mock.patch(
        "proton.keyring_linux.linuxkeyring.KeyringBackendLinux._KeyringBackendLinux__keyring_service",
        new_callable=mock.PropertyMock
    )
    def test_set_and_get_item_in_keyring(self, mock_keyring_service, cleanup_env):
        test_value = ["test-key"]
        mock_keyring_service.return_value = TEST_SERVICE
        k = KeyringBackendLinuxSecretService()
        k[TEST_KEY] = test_value
        assert k[TEST_KEY] == test_value

    @mock.patch(
        "proton.keyring_linux.linuxkeyring.KeyringBackendLinux._KeyringBackendLinux__keyring_service",
        new_callable=mock.PropertyMock
    )
    def test_set_and_del_item_in_keyring(self, mock_keyring_service, cleanup_env):
        mock_keyring_service.return_value = TEST_SERVICE
        k = KeyringBackendLinuxSecretService()
        k[TEST_KEY] = ["test-key"]
        del k[TEST_KEY]
        with pytest.raises(KeyError):
            k[TEST_KEY]
