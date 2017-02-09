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
import tempfile
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import covata.delta.crypto as crypto
import covata.delta.api as api


@pytest.yield_fixture(scope="session")
def temp_directory():
    directory = tempfile.mkdtemp()
    yield directory
    shutil.rmtree(directory)


@pytest.fixture(scope="session")
def crypto_service(temp_directory):
    return crypto.CryptoService(temp_directory, b"passphrase")


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=4096,
                                    backend=default_backend())


@pytest.fixture(scope="session")
def key2bytes():
    def convert(key):
        if isinstance(key, rsa.RSAPrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
        elif isinstance(key, rsa.RSAPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1)
    return convert


@pytest.fixture(scope="function")
def mock_signer(mocker, crypto_service):
    return mocker.patch.object(crypto_service, "signer",
                               return_value=mocker.Mock())


@pytest.fixture(scope="session")
def api_client(crypto_service):
    return api.RequestsApiClient(crypto_service)
