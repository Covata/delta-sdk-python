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

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests


def test_generate_key_pairs(crypto_service):
    private_key = crypto_service.generate_key()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    public_key = private_key.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_serialize_public_key_to_b64_encoded_der_subject_public_key_info_format(
        crypto_service, private_key):
    public_key = private_key.public_key()

    expected = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))  # type: bytes

    assert crypto_service.serialized(public_key) == expected.decode()


def test_decrypt_private_key(crypto_service, private_key, key2bytes):
    crypto_service.save(private_key, "mock.pem")
    retrieved = key2bytes(crypto_service.load("mock.pem"))
    expected = key2bytes(private_key)
    assert retrieved == expected


def test_encrypt_to_file(mocker, crypto_service, private_key):
    mock_makedirs = mocker.patch('os.makedirs')
    mocker.patch('os.path.isdir', return_value=False)
    crypto_service.save(private_key, "mock.pem")
    mock_makedirs.assert_called_once_with(crypto_service.key_store_path)


def test_compute_sha256_hex_digest(crypto_service):
    assert crypto_service.sha256hex("test") == \
           b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_construct_signer(mocker, crypto_service, private_key):
    load = mocker.patch.object(crypto_service, 'load', return_value=private_key)
    signer = crypto_service.signer("mock")

    r = requests.Request(url='https://test.com/stage/resource',
                         method='POST',
                         headers=dict(someKey="some value"),
                         json=dict(content="abcd"))
    signer(r.prepare())
    load.assert_called_once_with("mock.signing.pem")
