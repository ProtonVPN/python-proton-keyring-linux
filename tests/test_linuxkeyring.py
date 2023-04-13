"""
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
from proton.keyring_linux.core import KeyringBackendLinux
import pytest
from unittest import mock
import json
from proton.keyring.exceptions import KeyringError
from keyring import errors


@pytest.fixture
def mock_backend():
    return mock.Mock()


@pytest.fixture
def keyring_service():
    return KeyringBackendLinux._KeyringBackendLinux__keyring_service


def test_get_item(mock_backend, keyring_service):
    assert_value = {"test-key": "test-value"}
    mock_backend.get_password.return_value = json.dumps(assert_value)
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    assert k._get_item("key-test-get") == assert_value
    mock_backend.get_password.assert_called_once_with(keyring_service, "key-test-get")


def test_del_item(mock_backend, keyring_service):
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    k._del_item("key-test-del")
    mock_backend.delete_password.assert_called_once_with(keyring_service, "key-test-del")


def test_set_item(mock_backend, keyring_service):
    assert_key = "key-test-set"
    assert_value = {"test-key": "test-value"}
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    k._set_item(assert_key, assert_value)
    mock_backend.set_password.assert_called_once_with(keyring_service, assert_key, json.dumps(assert_value))


def test_get_item_raises_exception_with_keyring_issues(mock_backend, keyring_service):
    mock_backend.get_password.side_effect = errors.KeyringError()
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyringError):
        k._get_item("test")


def test_get_item_raises_exception_no_data(mock_backend, keyring_service):
    mock_backend.get_password.return_value = None
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyError):
        k._get_item("test")


def test_get_item_raises_exception_corrupted_data(mock_backend, keyring_service):
    mock_backend.get_password.return_value = "corrupted-data"
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyError):
        k._get_item("test")


def test_del_item_raises_exception_missing_key(mock_backend, keyring_service):
    mock_backend.delete_password.side_effect = errors.PasswordDeleteError()
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyError):
        k._del_item("test")


def test_del_item_raises_exception_keyring_error(mock_backend, keyring_service):
    mock_backend.delete_password.side_effect = errors.KeyringError()
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyringError):
        k._del_item("test")


def test_set_item_raises_exception_keyring_unable_to_add(mock_backend, keyring_service):
    mock_backend.set_password.side_effect = errors.PasswordSetError()
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyError):
        k._set_item("test", ["test"])


def test_set_item_raises_exception_keyring_error(mock_backend, keyring_service):
    mock_backend.set_password.side_effect = errors.KeyringError()
    k = KeyringBackendLinux(keyring_backend=mock_backend)
    with pytest.raises(KeyringError):
        k._set_item("test", ["test"])
