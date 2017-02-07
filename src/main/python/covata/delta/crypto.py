#   Copyright 2016 Covata Limited or its affiliates
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CryptoService:
    def __init__(self,
                 key_store_path,
                 key_store_passphrase):
        # type: (str, str) -> self
        """
        Constructs a new Crypto service with the given configuration.

        :param str key_store_path: the path to the private key store
        :param str key_store_passphrase: the passphrase to decrypt the keys
        """
        self.key_store_path = os.path.expanduser(key_store_path)
        self.key_store_passphrase = key_store_passphrase

    def save(self, private_key, file_name):
        # type: (rsa.RSAPrivateKey, str) -> None
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(self.key_store_passphrase))

        file_path = os.path.join(self.key_store_path, file_name)
        if not os.path.isdir(self.key_store_path):
            os.makedirs(self.key_store_path)

        with open(file_path, 'w') as f:
            f.write(pem.decode(encoding='utf8'))

    def load(self, file_name):
        # type: (str) -> rsa.RSAPrivateKey
        """

        :param file_name:
        :return:
        """
        file_path = os.path.join(self.key_store_path, file_name)
        with(open(file_path, 'r')) as f:
            return serialization \
                .load_pem_private_key(f.read(),
                                      password=self.key_store_passphrase,
                                      backend=default_backend())

    @staticmethod
    def generate_key():
        # type: () -> rsa.RSAPrivateKey
        """
        Generates an RSA private key object. The public key object can be
        extracted by calling public_key() method on the generated key object.

        >>> private_key = CryptoService.generate_key() # generate a private key
        >>> public_key = private_key.public_key() # get associated public key

        :return: the generated private key
        """
        return rsa.generate_private_key(public_exponent=65537,
                                        key_size=4096,
                                        backend=default_backend())

    @staticmethod
    def serialized(public_key):
        # type: (rsa.RSAPublicKey) -> unicode
        """

        :param :class:`RSAPublicKey` public_key: the public Key object
        :return: the key as base64 encoded string

        """
        der = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                      format=serialization.PublicFormat.PKCS1)
        return base64.b64encode(der).decode(encoding='utf8')
