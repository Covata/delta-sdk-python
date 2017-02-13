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

from covata.delta.crypto import generate_key, serialize_public_key, sha256hex


def test_generate_key_pairs():
    private_key = generate_key()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    public_key = private_key.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_serialize_public_key_to_b64_encoded_der_subject_public_key_info_format(
        private_key):
    public_key = private_key.public_key()

    expected = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))  # type: bytes

    assert serialize_public_key(public_key) == expected.decode()


def test_compute_sha256_hex_digest():
    assert sha256hex("test") == \
           b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
