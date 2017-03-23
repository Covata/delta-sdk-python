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

from . import crypto, apiclient
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

    def __init__(self, key_store, api_client_factory=apiclient.ApiClient):
        """
        Creates a new DeltaClient instance from the provided configuration.

        :param key_store: the key store
        :type key_store: :class:`~.DeltaKeyStore`
        :param api_client_factory: the API client factory
        :type api_client_factory:
           (:class:`~.DeltaKeyStore`) -> :class:`~.ApiClient`
        """
        self.__key_store = key_store
        self.__api_client = api_client_factory(key_store)

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
        :return: a generator of :class:`~.Identity` satisfying the request
        :rtype: generator of :class:`~.Identity`
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
        :return: a generator of audit events
        :rtype: generator of :class:`~.Event`
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
                event_id=event["id"],
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

    def get_secrets(self,
                    identity_id,
                    base_secret_id=None,
                    created_by=None,
                    rsa_key_owner_id=None,
                    metadata=None,
                    lookup_type=apiclient.SecretLookupType.any,
                    page=None,
                    page_size=None):
        """
        Gets a list of secrets based on the query parameters, bound by the
        pagination parameters.

        :param str identity_id: the authenticating identity id
        :param base_secret_id: the id of the base secret
        :type base_secret_id: str | None
        :param created_by: the id of the secret creator
        :type created_by: str | None
        :param rsa_key_owner_id: the id of the RSA key owner
        :type rsa_key_owner_id: str | None
        :param metadata: the metadata associated with the secret
        :type metadata: dict[str, str] | None
        :param lookup_type: the type of the lookup query
        :type lookup_type: :class:`~.SecretLookupType`
        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None
        :return: a generator of secrets satisfying the search criteria
        :rtype: generator of :class:`~.Secret`
        """
        secrets = self.api_client.get_secrets(
            identity_id, base_secret_id, created_by, rsa_key_owner_id,
            metadata, lookup_type, page, page_size)
        for secret in secrets:
            yield Secret(self,
                         secret_id=secret["id"],
                         created=secret["created"],
                         rsa_key_owner=secret.get("rsaKeyOwner"),
                         created_by=secret["createdBy"],
                         encryption_details=None,
                         base_secret_id=secret.get("baseSecret"))

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
            base_secret_id=secret.secret_id,
            rsa_key_owner_id=recipient.identity_id)

        return self.get_secret(recipient.identity_id, response["id"])

    def delete_secret(self, identity_id, secret_id):
        """
        Deletes the secret with the given secret id.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id
        """
        self.api_client.delete_secret(identity_id, secret_id)

    def get_secret_metadata(self, identity_id, secret_id):
        """
        Gets the metadata key and value pairs for the given secret.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret metadata dictionary and version tuple
        :rtype: (dict[str, str], int)
        """
        return self.api_client.get_secret_metadata(identity_id, secret_id)

    def add_secret_metadata(self, identity_id, secret_id, metadata):
        """
        Adds metadata to the given secret. The version number is required for
        optimistic locking on concurrent updates. An attempt to update metadata
        with outdated version will be rejected by the server. Passing in an
        empty metadata map will result in no changes to the metadata or
        version number.

        :param str identity_id: the authenticating identity id
        :param str secret_id: the secret id
        :param metadata: a map of metadata key and value pairs
        :type metadata: dict[str, str]
        """
        existing_metadata, existing_version = \
            self.get_secret_metadata(identity_id, secret_id)

        updated_metadata = existing_metadata.copy()
        updated_metadata.update(metadata)

        self.api_client.update_secret_metadata(
            identity_id, secret_id, updated_metadata, existing_version)


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
        :type parent: :class:`~.Client`
        :param identity_id: the id of the identity
        :param str public_encryption_key: the public signing key of the identity
        :param external_id: the external id of the identity
        :type external_id: str | None
        :param metadata: the metadata belonging to the identity
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

    def get_identity(self, identity_to_retrieve=None):
        """
        Gets the identity matching the given identity id.

        :type identity_to_retrieve: str | None
        :return: the identity
        :rtype: :class:`~.Identity`
        """
        return self.parent.get_identity(self.identity_id, identity_to_retrieve)

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
        :return: a generator of :class:`~.Identity` satisfying the request
        :rtype: generator of [:class:`~.Identity`]
        """
        return self.parent.get_identities_by_metadata(
            self.identity_id, metadata, page, page_size)

    def get_events(self, secret_id=None, rsa_key_owner_id=None):
        """
        Gets a list of events associated filtered by secret id or RSA key owner
        or both secret id and RSA key owner.

        :param secret_id: the secret id of interest
        :type secret_id: str | None
        :param rsa_key_owner_id: the rsa key owner id of interest
        :type rsa_key_owner_id: str | None
        :return: a generator of audit events
        :rtype: generator of :class:`~.Event`
        """
        return self.parent.get_events(
            self.identity_id, secret_id, rsa_key_owner_id)

    def get_secrets(self,
                    base_secret_id=None,
                    created_by=None,
                    rsa_key_owner_id=None,
                    metadata=None,
                    lookup_type=apiclient.SecretLookupType.any,
                    page=None,
                    page_size=None):
        """
        Gets a list of secrets based on the query parameters, bound by the
        pagination parameters.

        :param base_secret_id: the id of the base secret
        :type base_secret_id: str | None
        :param created_by: the id of the secret creator
        :type created_by: str | None
        :param rsa_key_owner_id: the id of the RSA key owner
        :type rsa_key_owner_id: str | None
        :param metadata: the metadata associated with the secret
        :type metadata: dict[str, str] | None
        :param lookup_type: the type of the lookup query
        :type lookup_type: :class:`~.SecretLookupType`
        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None
        :return: a generator of secrets satisfying the search criteria
        :rtype: generator of :class:`~.Secret`
        """
        return self.parent.get_secrets(
            self.identity_id, base_secret_id, created_by, rsa_key_owner_id,
            metadata, lookup_type, page, page_size)

    def create_secret(self, content):
        """
        Creates a new secret in Delta with the given contents.

        :param bytes content: the secret content
        :return: the secret
        :rtype: :class:`~.Secret`
        """
        return self.parent.create_secret(self.identity_id, content)

    def retrieve_secret(self, secret_id):
        """
        Retrieves a secret with this identity.

        :param str secret_id: the secret id
        :return: the secret
        :rtype: :class:`~.Secret`
        """
        return self.parent.get_secret(self.identity_id, secret_id)

    def delete_secret(self, secret_id):
        """
        Deletes the secret with the given secret id.

        :param str secret_id: the secret id
        """
        self.parent.delete_secret(self.identity_id, secret_id)

    def __repr__(self):
        return "{cls}(identity_id={identity_id})".format(
            cls=self.__class__.__name__, identity_id=self.identity_id)


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

    def __init__(self, parent, secret_id, created, rsa_key_owner, created_by,
                 encryption_details, base_secret_id=None):
        """
        Creates a new secret with the given parameters.

        :param parent: the Delta client that constructed this instance
        :type parent: :class:`~.Client`
        :param str secret_id: the id of the secret
        :param str created: the created date
        :param str rsa_key_owner: the identity id of the RSA key owner
        :param str created_by: the identity id of the secret creator
        :param encryption_details: the encryption details of the secret
        :type encryption_details: :class:`~.EncryptionDetails`
        """
        self.__parent = parent
        self.__secret_id = secret_id
        self.__created = created
        self.__rsa_key_owner = rsa_key_owner
        self.__created_by = created_by
        self.__encryption_details = encryption_details
        self.__base_secret_id = base_secret_id

    @property
    def parent(self):
        return self.__parent

    @property
    def secret_id(self):
        return self.__secret_id

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
            self.secret_id,
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
            self.secret_id)

    def get_events(self, rsa_key_owner_id=None):
        """
        Gets a list of events associated filtered by this secret id or
        both this secret id and RSA key owner.

        The credentials of the secret creator must be present in the local
        key store.

        :param rsa_key_owner_id: the rsa key owner id of interest
        :type rsa_key_owner_id: str | None
        :return: a generator of audit events
        :rtype: generator of :class:`~.Event`
        """
        return self.parent.get_events(self.created_by, self.secret_id,
                                      rsa_key_owner_id)

    def get_derived_secrets(self, page=None, page_size=None):
        """
        Gets a list of secrets derived from this secret, bound by the pagination
        parameters.

        The credentials of the secret creator be present in the local
        key store.

        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None

        :return: a generator of secrets
        :rtype: generator of :class:`~.Secret`
        """

        self.parent.get_secrets(requestor_id=self.created_by,
                                base_secret_id=self.secret_id,
                                page=page,
                                page_size=page_size)

    def add_metadata(self, metadata):
        """
        Adds the key and value pairs in the provided map as metadata for this
        secret. If the metadata previously contained a mapping for the key, the
        old value is replaced by the specified value.

        :param metadata: a map of metadata key and value pairs
        :type metadata: dict[str, str]
        """
        self.parent.add_secret_metadata(
            self.created_by, self.secret_id, metadata)

    def get_metadata(self):
        """
        Gets the metadata for this secret. Metadata are key-value pairs of
        strings that can be added to a secret to facilitate description and
        lookup. Secrets can support any number of metadata elements, but each
        key or value has a limit of 256 characters.

        :return: the metadata for this secret
        :rtype: dict[str, str]
        """
        metadata, version = self.parent.get_secret_metadata(self.created_by,
                                                            self.secret_id)
        return metadata

    def __repr__(self):
        return "{cls}(secret_id={secret_id})".format(
            cls=self.__class__.__name__, secret_id=self.secret_id)


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
                 event_id,
                 source_ip,
                 timestamp,
                 event_type):
        """
        Creates a new :class:`~.Event` with the given parameters.

        :param event_details: details of the audit event.
        :type event_details: :class:`~.EventDetails`
        :param str host: the host address
        :param str event_id: the identifier of the event object
        :param str source_ip: the source IP address
        :param timestamp: the timestamp of the event
        :type timestamp: datetime
        :param str event_type: the type of the event
        """
        self.__event_details = event_details
        self.__host = host
        self.__event_id = event_id
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
    def event_id(self):
        return self.__event_id

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
        return "{cls}(event_id={event_id})".format(
            cls=self.__class__.__name__, event_id=self.event_id)
