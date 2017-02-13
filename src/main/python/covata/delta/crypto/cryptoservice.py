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
from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

__all__ = ["generate_key", "serialize_public_key", "sha256hex"]


def generate_key():
    # type: () -> rsa.RSAPrivateKey
    """
    Generates an RSA private key object. The public key object can be
    extracted by calling public_key() method on the generated key object.

    >>> private_key = FileSystemKeyStore.generate_key() # generate a private key
    >>> public_key = private_key.public_key() # get associated public key

    :return: the generated private key object
    """
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=4096,
                                    backend=default_backend())


def serialize_public_key(public_key):
    # type: (rsa.RSAPublicKey) -> unicode
    """
    Serializes the provided public key object as base-64-encoded DER format
    using X.509 SubjectPublicKeyInfo with PKCS1.

    :param public_key: the public Key object
    :type public_key: :class:`RSAPublicKey`
    :return: the key as base64 encoded unicode string
    :rtype: str
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode(encoding='utf-8')


def sha256hex(payload):
    """
    Calculates the SHA256 hex digest of the given payload.

    :param str payload: the payload to be calculated
    :return: SHA256 hex digest
    :rtype: bytes
    """
    # type: (str) -> bytes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(payload if payload is bytes else payload.encode('utf-8'))
    x = digest.finalize()  # type: bytes
    return hexlify(x)
