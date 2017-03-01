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

from base64 import b64encode, b64decode

from . import crypto
from collections import namedtuple
from datetime import datetime


class Client:
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
        :type external_id: str | None
        :param metadata: the metadata to associate with the identity
        :type metadata: dict[str, str] | None
        :return: the identity
        :rtype: :class:`~.Identity`
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

        :param str identity_id: the authenticating identity id
        :type identity_to_retrieve: str | None
        :return: the identity
        :rtype: :class:`~.Identity`
        """
        response = self.api_client.get_identity(
            identity_id,
            identity_to_retrieve if identity_to_retrieve else identity_id)

        return Identity(self,
                        response["id"],
                        response["cryptoPublicKey"],
                        response.get("externalId"),
                        response.get("metadata"))

    def get_identities_by_metadata(self, identity_id, metadata,
                                   page=None, page_size=None):
        """
        Gets a list of identities matching the given metadata key and value
        pairs, bound by the pagination parameters.

        :param str identity_id: the authenticating identity id
        :param metadata: the metadata key and value pairs to filter
        :type metadata: dict[str, str]
        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None
        :return: a list of :class:`~.Identity` objects satisfying the request
        :rtype: list[:class:`~.Identity`]
        """
        identities = self.api_client.get_identities_by_metadata(
            identity_id, metadata, page, page_size)
        for identity in identities:
            yield Identity(self,
                           identity["id"],
                           identity["cryptoPublicKey"],
                           identity.get("externalId"),
                           identity.get("metadata"))

    def get_events(self, identity_id, secret_id=None, rsa_key_owner_id=None):
        """
        Gets a list of events associated filtered by secret id or RSA key owner
        or both secret id and RSA key owner.

        :param str identity_id: the authenticating identity id
        :param secret_id: the secret id of interest
        :type secret_id: str | None
        :param rsa_key_owner_id: the rsa key owner id of interest
        :type rsa_key_owner_id: str | None
        :return: a list of audit events
        :rtype: list[:class:`~.Event`]
        """
        events = self.api_client.get_events(
            identity_id, secret_id, rsa_key_owner_id)
        for event in events:
            details = event["eventDetails"]
            timestamp = event["timestamp"]
            yield Event(
                event_details=EventDetails(
                    base_secret_id=details.get("baseSecretId"),
                    requestor_id=details.get("requesterId"),
                    rsa_key_owner_id=details.get("rsaKeyOwnerId"),
                    secret_id=details.get("secretId"),
                    secret_owner_id=details.get("secretOwnerId")
                ),
                host=event["host"],
                id=event["id"],
                source_ip=event["sourceIp"],
                timestamp=datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ"),
                event_type=event["type"]
            )

    def create_secret(self, identity_id, content):
        """
        Creates a new secret in Delta with the given byte contents.

        :param str identity_id: the authenticating identity id
        :param bytes content: the secret contents
        :return: the secret
        :rtype: :class:`~.Secret`
        """
        secret_key = crypto.generate_secret_key()
        iv = crypto.generate_initialisation_vector()

        public_key = self.key_store.get_private_encryption_key(
            identity_id).public_key()

        encrypted_key = crypto.encrypt_key_with_public_key(secret_key,
                                                           public_key)
        cipher_text, tag = crypto.encrypt(content, secret_key, iv)
        response = self.api_client.create_secret(
            requestor_id=identity_id,
            content=b64encode(cipher_text + tag).decode('utf-8'),
            encryption_details=dict(
                symmetricKey=b64encode(encrypted_key).decode('utf-8'),
                initialisationVector=b64encode(iv).decode('utf-8')
            ))

        return self.get_secret(identity_id, response["id"])

    def get_secret(self, identity_id, secret_id):
        """
        Gets the given secret by id.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the id of the secret to retrieve
        :return: the secret
        :rtype: :class:`~.Secret`
        """
        response = self.api_client.get_secret(identity_id, secret_id)

        return Secret(self,
                      response["id"],
                      response["created"],
                      response["rsaKeyOwner"],
                      response["createdBy"],
                      EncryptionDetails(
                          response["encryptionDetails"]["symmetricKey"],
                          response["encryptionDetails"]["initialisationVector"]
                      ),
                      response.get("baseSecretId"))

    def get_secret_content_encrypted(self, identity_id, secret_id):
        """
        Gets the base64 encoded encrypted content given the secret id.

        Note that the returned encrypted content when decoded from base64 has a
        trailing 16 byte GCM authentication tag appended (i.e. the cipher text
        is the byte range [:-16] and the authentication tag is the remaining
        [-16:] bytes).

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id
        :return: the encrypted content encoded in base64
        :rtype: str
        """
        return self.api_client.get_secret_content(identity_id, secret_id)

    def get_secret_content(self, identity_id, secret_id, symmetric_key,
                           initialisation_vector):
        """
        Gets the plaintext content, given the symmetric key and
        initialisation vector used for encryption.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id
        :param str symmetric_key:
            the symmetric key used for encryption encoded in base64
        :param str initialisation_vector:
            the initialisation vector encoded in base64
        :return: the plaintext content of the secret
        :rtype: bytes
        """
        encrypted_content = b64decode(
            self.get_secret_content_encrypted(identity_id, secret_id))

        decrypted_key = crypto.decrypt_with_private_key(
            b64decode(symmetric_key),
            self.key_store.get_private_encryption_key(identity_id))

        return crypto.decrypt(encrypted_content[:-16],
                              encrypted_content[-16:],
                              decrypted_key,
                              b64decode(initialisation_vector))

    def share_secret(self, identity_id, recipient_id, secret_id):
        """
        Shares the base secret with the specified recipient. The contents will
        be encrypted with the public encryption key of the RSA key owner, and a
        new secret key and initialisation vector will be generated. This call
        will result in a new derived secret being created and returned.

        :param str identity_id: the authenticating identity id
        :param str recipient_id: the target identity id to share the base secret
        :param str secret_id: the base secret id
        :return: the derived secret
        :rtype: :class:`~.Secret`
        """
        recipient = self.get_identity(identity_id, recipient_id)
        secret = self.get_secret(identity_id, secret_id)

        secret_key = crypto.generate_secret_key()
        iv = crypto.generate_initialisation_vector()

        public_key = crypto.deserialize_public_key(
            recipient.public_encryption_key)

        encrypted_key = crypto.encrypt_key_with_public_key(secret_key,
                                                           public_key)
        cipher_text, tag = crypto.encrypt(secret.get_content(), secret_key, iv)
        response = self.api_client.share_secret(
            requestor_id=identity_id,
            content=b64encode(cipher_text + tag).decode('utf-8'),
            encryption_details=dict(
                symmetricKey=b64encode(encrypted_key).decode('utf-8'),
                initialisationVector=b64encode(iv).decode('utf-8')),
            base_secret_id=secret.id,
            rsa_key_owner_id=recipient.id)

        return self.get_secret(recipient.id, response["id"])

    def delete_secret(self, identity_id, secret_id):
        """
        Deletes the secret with the given secret id.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id
        """
        self.api_client.delete_secret(identity_id, secret_id)


class Identity:
    """
    An instance of this class encapsulates an identity in Covata Delta. An
    identity can be a user, application, device or any other identifiable
    entity that can create secrets and/or be target recipient of a secret.

    An has two sets of asymmetric keys, for encryption and for signing of
    requests. Identities may also have optional, public, searchable metadata
    and a reference to an identifier in an external system.
    """

    def __init__(self, parent, id, public_encryption_key,
                 external_id, metadata):
        """
        Creates a new identity in Delta with the provided metadata
        and external id.

        :param parent: the Delta client that constructed this instance
        :type parent: :class:`~.Client`
        :param id: the id of the identity
        :param str public_encryption_key: the public signing key of the identity
        :param external_id: the external id of the identity
        :type external_id: str | None
        :param metadata: the metadata belonging to the identity
        :type metadata: dict[str, str] | None
        """
        self.__parent = parent
        self.__id = id
        self.__public_encryption_key = public_encryption_key
        self.__external_id = external_id
        self.__metadata = metadata

    @property
    def parent(self):
        return self.__parent

    @property
    def id(self):
        return self.__id

    @property
    def public_encryption_key(self):
        return self.__public_encryption_key

    @property
    def external_id(self):
        return self.__external_id

    @property
    def metadata(self):
        return self.__metadata

    def get_identity(self, identity_to_retrieve=None):
        """
        Gets the identity matching the given identity id.

        :type identity_to_retrieve: str | None
        :return: the identity
        :rtype: :class:`~.Identity`
        """
        return self.parent.get_identity(self.id, identity_to_retrieve)

    def get_identities_by_metadata(self, metadata, page=None, page_size=None):
        """
        Gets a list of identities matching the given metadata key and value
        pairs, bound by the pagination parameters.

        :param metadata: the metadata key and value pairs to filter
        :type metadata: dict[str, str]
        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None
        :return: a list of :class:`~.Identity` objects satisfying the request
        :rtype: list[:class:`~.Identity`]
        """
        return self.parent.get_identities_by_metadata(
            self.id, metadata, page, page_size)

    def get_events(self, secret_id=None, rsa_key_owner_id=None):
        """
        Gets a list of events associated filtered by secret id or RSA key owner
        or both secret id and RSA key owner

        :param secret_id: the secret id of interest
        :type secret_id: str | None
        :param rsa_key_owner_id: the rsa key owner id of interest
        :type rsa_key_owner_id: str | None
        :return: a list of audit events
        :rtype: list[:class:`~.Event`]
        """
        return self.parent.get_events(self.id, secret_id, rsa_key_owner_id)

    def create_secret(self, content):
        """
        Creates a new secret in Delta with the given contents.

        :param bytes content: the secret content
        :return: the secret
        :rtype: :class:`~.Secret`
        """
        return self.parent.create_secret(self.id, content)

    def delete_secret(self, secret_id):
        """
        Deletes the secret with the given secret id.

        :param str secret_id: the secret id
        """
        self.parent.delete_secret(self.id, secret_id)

    def __repr__(self):
        return "{cls}(id={id})".format(cls=self.__class__.__name__, id=self.id)


class Secret:
    """
    An instance of this class encapsulates a secret in Covata Delta. A
    secret has contents, which is encrypted by a symmetric key algorithm as
    defined in the immutable EncryptionDetails class, holding information such
    as the symmetric (secret) key, initialisation vector and algorithm. The
    symmetric key is encrypted with the public encryption key of the RSA key
    owner. This class will return the decrypted contents and symmetric key if
    returned as a result of Client.
    """

    def __init__(self, parent, id, created, rsa_key_owner, created_by,
                 encryption_details, base_secret_id=None):
        """
        Creates a new secret with the given parameters.

        :param parent: the Delta client that constructed this instance
        :type parent: :class:`~.Client`
        :param str id: the id of the secret
        :param str created: the created date
        :param str rsa_key_owner: the identity id of the RSA key owner
        :param str created_by: the identity id of the secret creator
        :param encryption_details: the encryption details of the secret
        :type encryption_details: :class:`~.EncryptionDetails`
        """
        self.__parent = parent
        self.__id = id
        self.__created = created
        self.__rsa_key_owner = rsa_key_owner
        self.__created_by = created_by
        self.__encryption_details = encryption_details
        self.__base_secret_id = base_secret_id

    @property
    def parent(self):
        return self.__parent

    @property
    def id(self):
        return self.__id

    @property
    def created(self):
        return self.__created

    @property
    def rsa_key_owner(self):
        return self.__rsa_key_owner

    @property
    def created_by(self):
        return self.__created_by

    @property
    def encryption_details(self):
        return self.__encryption_details

    @property
    def base_secret_id(self):
        return self.__base_secret_id

    def get_content(self):
        """
        Gets the content of a secret, encrypted with the details defined in the
        encryption_details of this secret and encoded in base64.

        :return: the content of the secret encoded in base64
        :rtype: str
        """
        return self.parent.get_secret_content(
            self.rsa_key_owner,
            self.id,
            self.encryption_details.symmetric_key,
            self.encryption_details.initialisation_vector)

    def share_with(self, identity_id):
        """
        Shares this secret with the target recipient identity. This action
        will create a new (derived) secret in Covata Delta, and the new
        secret will be returned to the caller.

        The credentials of the RSA key owner must be present in the local
        key store.

        :param str identity_id: the recipient identity id
        :return: the derived secret
        :rtype: :class:`~.Secret`
        """
        return self.parent.share_secret(
            self.created_by,
            identity_id,
            self.id)

    def get_events(self, rsa_key_owner_id=None):
        """
        Gets a list of events associated filtered by this secret id or
        both this secret id and RSA key owner.

        The credentials of the secret creator must be present in the local
        key store.

        :param rsa_key_owner_id: the rsa key owner id of interest
        :type rsa_key_owner_id: str | None
        :return: a list of audit events
        :rtype: list[:class:`~.Event`]
        """
        return self.parent.get_events(self.created_by, self.id,
                                      rsa_key_owner_id)

    def __repr__(self):
        return "{cls}(id={id})".format(cls=self.__class__.__name__, id=self.id)


class EncryptionDetails:
    """
    This class holds the necessary key materials required to decrypt a
    particular secret. The symmetric key itself is protected by a public
    encryption key belonging to an identity.
    """

    def __init__(self, symmetric_key, initialisation_vector):
        """
        Creates a new encryption details with the given parameters.

        :param str symmetric_key: the symmetric key
        :param str initialisation_vector: the initialisation vector
        """
        self.__symmetric_key = symmetric_key
        self.__initialisation_vector = initialisation_vector

    @property
    def symmetric_key(self):
        return self.__symmetric_key

    @property
    def initialisation_vector(self):
        return self.__initialisation_vector


class EventDetails(namedtuple("EventDetails", [
    "base_secret_id", "requestor_id", "rsa_key_owner_id", "secret_id",
    "secret_owner_id"
])):
    """
    This class describes the details of an event related to a secret.
    Information includes the secret id, the owner identity id of the secret, and
    the identity id triggering the event.

    Additional information such as base secret id and
    RSA key owner id are also available for derived secrets.
    """

    def __init__(self, base_secret_id, requestor_id, rsa_key_owner_id,
                 secret_id, secret_owner_id):
        """
        Creates an instance of event details.

        :param str base_secret_id: the id of the base secret
        :param str requestor_id: the id of the requesting identity
        :param str rsa_key_owner_id: the id of the RSA key owner
        :param str secret_id: the id of the secret
        :param str secret_owner_id: the id of the secret owner
        """
        super(EventDetails, self).__init__()


class Event:
    """
    An instance of this class encapsulates an event in Covata Delta. An
    event is an audit entry representing an action undertaken by an
    identity on a secret.
    """

    def __init__(self,
                 event_details,
                 host,
                 id,
                 source_ip,
                 timestamp,
                 event_type):
        """
        Creates a new :class:`~.Event` with the given parameters.

        :param event_details: details of the audit event.
        :type event_details: :class:`~.EventDetails`
        :param str host: the host address
        :param str id: the identifier of the event object
        :param str source_ip: the source IP address
        :param timestamp: the timestamp of the event
        :type timestamp: datetime
        :param str event_type: the type of the event
        """
        self.__event_details = event_details
        self.__host = host
        self.__id = id
        self.__source_ip = source_ip
        self.__timestamp = timestamp
        self.__event_type = event_type

    @property
    def event_details(self):
        return self.__event_details

    @property
    def host(self):
        return self.__host

    @property
    def id(self):
        return self.__id

    @property
    def source_ip(self):
        return self.__source_ip

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def event_type(self):
        return self.__event_type

    def __repr__(self):
        return "{cls}(id={id})".format(cls=self.__class__.__name__, id=self.id)
