#   Copyright 2017 Covata Limited or its affiliates
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import pytest

from covata.delta.keystore import FileSystemKeyStore


@pytest.fixture(scope="function")
def fs_key_store(temp_directory):
    return FileSystemKeyStore(temp_directory, b"passphrase")


def test_decrypt_private_key(fs_key_store, private_key, key2bytes):
    fs_key_store.store_keys("mock", private_key, private_key)
    retrieved = key2bytes(fs_key_store.get_private_signing_key("mock"))
    expected = key2bytes(private_key)
    assert retrieved == expected


def test_encrypt_to_file(mocker, fs_key_store, private_key):
    mock_makedirs = mocker.patch('os.makedirs')
    mocker.patch('os.path.isdir', return_value=False)
    fs_key_store.store_keys("mock", private_key, private_key)
    mock_makedirs.assert_called_with(fs_key_store.key_store_path)


def test_save__should__fail_when_key_exists(fs_key_store, private_key):
    fs_key_store.store_keys("mock", private_key, private_key)
    with pytest.raises(IOError) as excinfo:
        fs_key_store.store_keys("mock", private_key, private_key)
    expected = \
        "Save failed: A key with name [mock.signing.pem] already exists"
    assert expected in str(excinfo.value)


def test_save__should__fail_when_type_is_not_rsaprivatekey(fs_key_store):
    with pytest.raises(TypeError) as excinfo:
        fs_key_store.store_keys("mock_id", "key", "crypto_key")
    expected = "private_key must be an instance of RSAPrivateKey, actual: str"
    assert expected in str(excinfo.value)
