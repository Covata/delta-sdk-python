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
import os
from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["generate_private_key", "serialize_public_key",
           "calculate_sha256hex", "generate_secret_key",
           "generate_initialization_vector", "encrypt", "decrypt"]


def generate_private_key():
    # type: () -> rsa.RSAPrivateKey
    """
    Generates an RSA private key object. The public key object can be
    extracted by calling public_key() method on the generated key object.

    >>> private_key = generate_private_key() # generate a private key
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


def calculate_sha256hex(payload):
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


def generate_initialization_vector():
    """
    Generates a 128 bits initialization vector.

    Uses ``/dev/urandom`` on UNIX platforms, and ``CryptGenRandom`` on Windows.

    :return: the 128 bits initialization vector
    :rtype: bytes
    """
    return os.urandom(16)


def generate_secret_key():
    """
    Generates a 256 bits secret key.

    Uses ``/dev/urandom`` on UNIX platforms, and ``CryptGenRandom`` on Windows.

    :return: the 256 bits secret key
    :rtype: bytes
    """
    return os.urandom(32)


def encrypt(data, secret_key, initialization_vector):
    # type: (bytes, bytes, bytes) -> (bytes, bytes)
    """
    Encrypts data using the given secret key and initialization vector.

    >>> from covata.delta import crypto
    >>> secret_key = crypto.generate_secret_key()
    >>> iv = crypto.generate_initialization_vector()
    >>> ciphertext, tag = crypto.encrypt(b"secret message", secret_key, iv)
    >>> plaintext = crypto.decrypt(cipher_text, tag, secret_key, iv)

    :param bytes data: the plaintext bytes to be encrypted
    :param secret_key: the key to be used for encryption
    :param initialization_vector: the initialisation vector
    :return: the ciphertext and GCM authentication tag tuple
    :rtype: tuple(bytes, bytes)
    """
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(initialization_vector=initialization_vector,
                                   min_tag_length=16),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()

    return cipher_text, encryptor.tag


def decrypt(ciphertext, tag, secret_key, initialization_vector):
    # type: (bytes, bytes, bytes, bytes) -> bytes
    """
    Decrypts a cipher text using the given GCM authentication tag,
    secret key and initialization vector.

    :param bytes ciphertext: the cipher text to be decrypted
    :param bytes tag: the GCM authentication tag
    :param bytes secret_key: the key to be used for encryption
    :param bytes initialization_vector: the initialisation vector
    :return: the decrypted plaintext
    :rtype: bytes
    """
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(initialization_vector=initialization_vector,
                                   tag=tag),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
