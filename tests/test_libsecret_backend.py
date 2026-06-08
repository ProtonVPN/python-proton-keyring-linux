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
import pytest
from unittest.mock import MagicMock
from proton.keyring_linux.libsecret import LibsecretKeyringBackend
from proton.keyring_linux.secretservice import KeyringBackendLinuxSecretService

@pytest.fixture
def mock_secret():
    mock_secret = MagicMock()
    mock_secret.SchemaFlags.NONE = 0
    mock_secret.SchemaAttributeType.STRING = "string"
    mock_secret.Schema.new.return_value = MagicMock()
    return mock_secret

def raise_value_error():
    raise ValueError

def test_libsecret_priority_is_lower_than_secretservice():
    assert LibsecretKeyringBackend._get_priority() < KeyringBackendLinuxSecretService._get_priority()

def test_validation_fails_when_libsecret_not_available():
    LibsecretKeyringBackend._secret_module = None
    LibsecretKeyringBackend._import_secret = staticmethod(raise_value_error)

    assert not LibsecretKeyringBackend._validate()

def test_get_secret_lazy_imports_when_not_cached(mock_secret):
    LibsecretKeyringBackend._secret_cache = None
    LibsecretKeyringBackend._import_secret = staticmethod(lambda: mock_secret)

    result = LibsecretKeyringBackend._get_secret()

    assert result is mock_secret

def test_get_secret_returns_cached_module_without_importing(mock_secret):
    LibsecretKeyringBackend._secret_cache = mock_secret

    result = LibsecretKeyringBackend._get_secret()

    assert result is mock_secret

def test_init_creates_correct_schema(mock_secret):
    #this test is a reminder to keep the schema compatible with secretservice
    LibsecretKeyringBackend._secret_cache = mock_secret
    backend = LibsecretKeyringBackend()

    mock_secret.Schema.new.assert_called_once_with(
        LibsecretKeyringBackend.SCHEMA,
        mock_secret.SchemaFlags.NONE,
        {
            "application": mock_secret.SchemaAttributeType.STRING,
            "service": mock_secret.SchemaAttributeType.STRING,
            "username": mock_secret.SchemaAttributeType.STRING,
        },
    )

def test_set_password_calls_sync_with_correct_args(mock_secret):
    LibsecretKeyringBackend._secret_cache = mock_secret
    backend = LibsecretKeyringBackend()
    backend.set_password("test-service", "test-key", "test-pass")

    mock_secret.password_store_sync.assert_called_once_with(
        backend.schema,
        {"application": "Python keyring library", "service": "test-service", "username": "test-key"},
        None,
        "test-key",
        "test-pass",
        None,
    )

def test_get_password_returns_password_when_found(mock_secret):
    mock_secret.password_lookup_sync.return_value = "test-password"
    LibsecretKeyringBackend._secret_cache = mock_secret
    backend = LibsecretKeyringBackend()

    assert backend.get_password("test-service", "test-key") == "test-password"

def test_get_password_returns_None_when_not_found(mock_secret):
    mock_secret.password_lookup_sync.return_value = None
    LibsecretKeyringBackend._secret_cache = mock_secret
    backend = LibsecretKeyringBackend()

    assert backend.get_password("test-service", "test-key") == None

def test_delete_password_calls_clear_sync_with_correct_args(mock_secret):
    LibsecretKeyringBackend._secret_cache = mock_secret
    backend = LibsecretKeyringBackend()

    backend.delete_password("test-service", "test-key")

    mock_secret.password_clear_sync.assert_called_once_with(
        backend.schema,
        {"application": "Python keyring library", "service": "test-service", "username": "test-key"},
        None,
    )


