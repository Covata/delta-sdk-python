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

from covata.delta import crypto


def test_generate_private_key():
    private_key = crypto.generate_private_key()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    public_key = private_key.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_serialize_public_key_to_b64_encoded_der_subject_public_key_info_format(
        private_key):
    public_key = private_key.public_key()

    expected = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))  # type: bytes

    assert crypto.serialize_public_key(public_key) == expected.decode()


def test_deserialize_public_key(private_key, key2bytes):
    public_key = private_key.public_key()
    serialized = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode('utf-8')
    deserialized = crypto.deserialize_public_key(serialized)
    assert key2bytes(deserialized) == key2bytes(public_key)


def test_compute_sha256_hex_digest():
    assert crypto.calculate_sha256hex("test") == \
           b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_generate_initialisation_vector(mocker):
    os_urandom = mocker.patch('os.urandom')
    crypto.generate_initialisation_vector()
    os_urandom.assert_called_once_with(16)


def test_generate_secret_key(mocker):
    os_urandom = mocker.patch('os.urandom')
    crypto.generate_secret_key()
    os_urandom.assert_called_once_with(32)


def test_encrypt_decrypt():
    plaintext = b"123"
    secret_key = b'a' * 32
    iv = b'a' * 16
    ciphertext, tag = crypto.encrypt(plaintext, secret_key, iv)
    assert crypto.decrypt(ciphertext, tag, secret_key, iv) == plaintext


def test_secret_key_encrypt_decrypt(private_key):
    secret_key = b'a' * 32

    public_encryption_key = private_key.public_key()

    ciphertext = crypto.encrypt_key_with_public_key(
        secret_key=secret_key,
        public_encryption_key=public_encryption_key)

    decrypted_secret_key = crypto.decrypt_with_private_key(
        secret_key=ciphertext,
        private_encryption_key=private_key)

    assert decrypted_secret_key == secret_key

