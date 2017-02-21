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

from __future__ import absolute_import

from . import crypto
from . import utils


class Client(utils.LogMixin):
    """
    The main entry point for the Delta SDK.

    An instance of this class will provide an interface to work and interact
    with the Delta API. The core domain objects (Identity, Secret and
    Event) are returned from method calls to this class, and themselves provide
    fluent interface that can be used to continue interactive with the Delta
    API. Consumers of this SDK can therefore choose whether they wish to
    construct all the calls from base values (i.e. id strings such as
    identity_id, secret_id, etc) or via the fluent interfaces (or a mixture of
    both).
    """

    def __init__(self, config):
        """
        Creates a new DeltaClient instance from the provided configuration.

        :param config: the configuration for the client
        :type config: dict[str, any]
        """
        self.__key_store = config["key_store"]
        self.__api_client = config["api_client"]

    @property
    def key_store(self):
        return self.__key_store

    @property
    def api_client(self):
        return self.__api_client

    def create_identity(self, external_id=None, metadata=None):
        """
        Creates a new identity in Delta.

        :param external_id: the external id to associate with the identity
        :param metadata: the metadata to associate with the identity
        :type external_id: str | None
        :type metadata: dict[str, str] | None
        :return: the identity
        :rtype: :class:`Identity`
        """
        private_signing_key = crypto.generate_private_key()
        private_encryption_key = crypto.generate_private_key()

        public_signing_key = crypto.serialize_public_key(
            private_signing_key.public_key())
        public_encryption_key = crypto.serialize_public_key(
            private_encryption_key.public_key())

        identity_id = self.api_client.register_identity(public_encryption_key,
                                                        public_signing_key,
                                                        external_id, metadata)

        self.key_store.store_keys(identity_id=identity_id,
                                  private_signing_key=private_signing_key,
                                  private_encryption_key=private_encryption_key)

        return Identity(self, identity_id, public_encryption_key,
                        external_id, metadata)

    def get_identity(self, identity_id, identity_to_retrieve=None):
        """
        Gets the identity matching the given identity id.

        :param identity_id: the authenticating identity id
        :type identity_to_retrieve: str | None
        :return: the identity
        :rtype: :class:`Identity`
        """
        response = self.api_client.get_identity(identity_id,
                                                identity_id
                                                if identity_to_retrieve is None
                                                else identity_to_retrieve)
        return Identity(self,
                        response.get("id"),
                        response.get("cryptoPublicKey"),
                        response.get("externalId"),
                        response.get("metadata"))


class Identity:
    """
    An instance of this class encapsulates an identity in Covata Delta. An
    identity can be a user, application, device or any other identifiable
    entity that can create secrets and/or be target recipient of a secret.

    An has two sets of asymmetric keys, for encryption and for signing of
    requests. Identities may also have optional, public, searchable metadata
    and a reference to an identifier in an external system.
    """

    def __init__(self, parent, identity_id, public_encryption_key,
                 external_id, metadata):
        """
        Creates a new identity in Delta with the provided metadata
        and external id.

        :param parent: the Delta client that constructed this instance
        :param public_encryption_key: the public signing key of the identity
        :param external_id: the external id of the identity
        :param metadata: the metadata belonging to the identity
        :type parent: :class:`Client`
        :type public_encryption_key: :class:`RSAPublicKey`
        :type external_id: str | None
        :type metadata: dict[str, str] | None
        """
        self.__parent = parent
        self.__identity_id = identity_id
        self.__public_encryption_key = public_encryption_key
        self.__external_id = external_id
        self.__metadata = metadata

    @property
    def parent(self):
        return self.__parent

    @property
    def identity_id(self):
        return self.__identity_id

    @property
    def public_encryption_key(self):
        return self.__public_encryption_key

    @property
    def external_id(self):
        return self.__external_id

    @property
    def metadata(self):
        return self.__metadata
