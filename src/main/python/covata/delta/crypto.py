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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["generate_private_key", "serialize_public_key",
           "calculate_sha256hex", "generate_secret_key",
           "generate_initialisation_vector", "encrypt", "decrypt",
           "encrypt_key_with_public_key", "decrypt_with_private_key",
           "deserialize_public_key"]


def generate_private_key():
    """
    Generates a :class:`~rsa.RSAPrivateKey` object. The public key object can be
    extracted by calling public_key() method on the generated key object.

    :return: the generated private key object
    :rtype: :class:`~rsa.RSAPrivateKey`
    """
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=4096,
                                    backend=default_backend())


def serialize_public_key(public_key):
    """
    Serializes the provided public key object as base-64-encoded DER format
    using X.509 SubjectPublicKeyInfo with PKCS1.

    :param public_key: the public key object
    :type public_key: :class:`~rsa.RSAPublicKey`
    :return: the key as base64 encoded unicode string
    :rtype: str
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode(encoding='utf-8')


def deserialize_public_key(b64_encoded_public_key):
    """
    loads a :class:`~rsa.RSAPublicKey` object from a serialized public key.

    :param str b64_encoded_public_key: the key as base64 encoded string
    :return: the public key object
    :rtype: :class:`~rsa.RSAPublicKey`
    """
    return serialization.load_der_public_key(
        data=base64.b64decode(b64_encoded_public_key.encode('utf-8')),
        backend=default_backend())


def calculate_sha256hex(payload):
    """
    Calculates the SHA256 hex digest of the given payload.

    :param str payload: the payload to be calculated
    :return: SHA256 hex digest
    :rtype: bytes
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(payload if payload is bytes else payload.encode('utf-8'))
    x = digest.finalize()  # type: bytes
    return hexlify(x)


def generate_initialisation_vector():
    """
    Generates a 128 bits initialisation vector.

    Uses ``/dev/urandom`` on UNIX platforms, and ``CryptGenRandom`` on Windows.

    :return: the 128 bits initialisation vector
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


def encrypt(data, secret_key, initialisation_vector):
    """
    Encrypts data using the given secret key and initialisation vector.

    :param bytes data: the plaintext bytes to be encrypted
    :param bytes secret_key: the key to be used for encryption
    :param bytes initialisation_vector: the initialisation vector
    :return: the cipher text and GCM authentication tag tuple
    :rtype: (bytes, bytes)
    """
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(initialization_vector=initialisation_vector,
                                   min_tag_length=16),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, encryptor.tag


def decrypt(ciphertext, tag, secret_key, initialisation_vector):
    """
    Decrypts a cipher text using the given GCM authentication tag,
    secret key and initialisation vector.

    :param bytes ciphertext: the cipher text to be decrypted
    :param bytes tag: the GCM authentication tag
    :param bytes secret_key: the key to be used for encryption
    :param bytes initialisation_vector: the initialisation vector
    :return: the decrypted plaintext
    :rtype: bytes
    """
    cipher = Cipher(algorithm=algorithms.AES(secret_key),
                    mode=modes.GCM(initialization_vector=initialisation_vector,
                                   tag=tag),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_key_with_public_key(secret_key, public_encryption_key):
    """
    Encrypts the given secret key with the public key.

    :param bytes secret_key: the key to encrypt
    :param public_encryption_key: the public encryption key
    :type public_encryption_key: :class:`~rsa.RSAPublicKey`
    :return: the encrypted key
    :rtype: bytes
    """
    return public_encryption_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


def decrypt_with_private_key(secret_key, private_encryption_key):
    """
    Decrypts the given secret key with the private key.

    :param bytes secret_key: the secret key to decrypt
    :param private_encryption_key: the private encryption key
    :type private_encryption_key: :class:`~rsa.RSAPrivateKey`
    :return: the decrypted key
    :rtype: bytes
    """
    return private_encryption_key.decrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
