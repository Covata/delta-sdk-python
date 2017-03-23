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
from base64 import b64encode

import pytest
import uuid

from covata.delta import Client, EventDetails, SecretLookupType
from datetime import datetime


@pytest.fixture(scope="function")
def client(api_client, key_store):
    return Client(key_store=key_store, api_client_factory=lambda x: api_client)


@pytest.fixture(scope="function")
def api_client(mocker):
    return mocker.MagicMock()


@pytest.fixture(scope="function")
def key_store(mocker):
    return mocker.MagicMock()


@pytest.fixture(scope="function")
def mock_crypto(mocker, private_key):
    iv = "01234567".encode('utf-8')
    key = "0123456789abcdef".encode('utf-8')

    mocker.patch('covata.delta.crypto.generate_secret_key',
                 return_value=key)

    mocker.patch('covata.delta.crypto.generate_initialisation_vector',
                 return_value=iv)

    mocker.patch('covata.delta.crypto.generate_private_key',
                 return_value=private_key)

    mocker.patch('covata.delta.crypto.deserialize_public_key',
                 return_value=private_key.public_key())

    mocker.patch('covata.delta.crypto.decrypt',
                 return_value=b'plaintext')

    mocker.patch('covata.delta.crypto.decrypt_with_private_key',
                 return_value=b'secret key')

    mocker.patch('covata.delta.crypto.encrypt',
                 return_value=('encrypted secret'.encode('utf-8'),
                               'tag'.encode('utf-8')))

    mocker.patch('covata.delta.crypto.encrypt_key_with_public_key',
                 return_value='encrypted key'.encode('utf-8'))

    return {"iv": iv, "key": key}


@pytest.mark.parametrize("ext_id", ["1", None])
@pytest.mark.parametrize("metadata", [dict(name="Bob"), None, {}])
def test_create_identity(mocker, client, api_client, key_store, private_key,
                         key2bytes, ext_id, metadata, mock_crypto):
    expected_id = str(uuid.uuid4())

    api_client.register_identity.return_value = expected_id
    identity = client.create_identity(ext_id, metadata)

    api_client.register_identity.assert_called_with(
        key2bytes(private_key.public_key()),
        key2bytes(private_key.public_key()),
        ext_id,
        metadata)

    key_store.store_keys.assert_called_with(
        identity_id=expected_id,
        private_signing_key=private_key,
        private_encryption_key=private_key)

    assert identity.identity_id == expected_id
    assert identity.external_id == ext_id if ext_id is not None \
        else identity.external_id is None
    assert identity.metadata == metadata if metadata is not None \
        else identity.metadata is None


@pytest.mark.parametrize("ext_id", ["1", None])
@pytest.mark.parametrize("metadata", [dict(name="Bob"), None])
def test_get_identity_empty_ext_id_and_metadata(mocker, client, api_client,
                                                ext_id, metadata):
    expected_id = str(uuid.uuid4())
    response = dict(version=1,
                    id=expected_id,
                    cryptoPublicKey="crypto_public_key",
                    externalId=ext_id,
                    metadata=metadata)
    response = dict((k, v) for k, v in response.items() if v is not None)

    mocker.patch.object(api_client, "get_identity", return_value=response)

    identity = client.get_identity(expected_id)
    ext_id_ = identity.external_id
    metadata_ = identity.metadata

    assert identity.parent == client
    assert identity.identity_id == expected_id
    assert ext_id_ == ext_id if ext_id else ext_id_ is None
    assert metadata_ == metadata if metadata else metadata_ is None
    assert identity.public_encryption_key == "crypto_public_key"


@pytest.mark.parametrize("identities", [
    [],
    [dict(id="id1",
          version=2,
          cryptoPublicKey="key1",
          externalId="ext1",
          metadata=dict(x="x")),
     dict(id="id2",
          version=2,
          cryptoPublicKey="key2",
          metadata=dict(x="x", x2="x2"))
     ]
], ids=["empty list", "list of identities"])
def test_get_identities_by_metadata(mocker, client, api_client, identities):
    mocker.patch.object(api_client, "get_identities_by_metadata",
                        return_value=identities)
    auth_id = str(uuid.uuid4())
    identities_ = list(client.get_identities_by_metadata(auth_id, dict(x="x")))

    assert len(identities) == len(identities_)

    for identity, identity_ in zip(identities, identities_):
        ext_id_ = identity_.external_id
        ext_id = identity.get("externalId")

        assert identity_.parent == client
        assert identity_.identity_id == identity["id"]
        assert identity_.public_encryption_key == identity["cryptoPublicKey"]
        assert identity_.metadata == identity["metadata"]
        assert ext_id_ == ext_id if ext_id is not None else ext_id_ is None


@pytest.mark.parametrize("auth_id", [str(uuid.uuid4())])
@pytest.mark.parametrize("identity_id", [None, str(uuid.uuid4())])
def test_get_identity(client, api_client, auth_id, identity_id):
    expected_id = auth_id if identity_id is None else identity_id
    api_client.get_identity.return_value = dict(
        version=1,
        id=expected_id,
        externalId="1",
        cryptoPublicKey="crypto_public_key",
        metadata=dict(name="Bob"))

    identity = client.get_identity(expected_id)

    assert identity.parent == client
    assert identity.identity_id == expected_id
    assert identity.external_id == "1"
    assert identity.metadata == dict(name="Bob")
    assert identity.public_encryption_key == "crypto_public_key"


def test_create_secret(client, api_client, key_store, private_key, mock_crypto):
    expected_id = str(uuid.uuid4())
    rsa_key_owner_id = str(uuid.uuid4())
    created_by_id = str(uuid.uuid4())

    key_store.get_private_encryption_key.return_value = private_key

    api_client.create_secret.return_value = dict(id=expected_id)
    api_client.get_secret.return_value = dict(
        id=expected_id,
        created="12345",
        rsaKeyOwner=rsa_key_owner_id,
        createdBy=created_by_id,
        encryptionDetails=dict(
            initialisationVector=mock_crypto["iv"],
            symmetricKey=mock_crypto["key"]))

    secret = client.create_secret(created_by_id,
                                  "this is my secret".encode('utf-8'))

    assert secret.parent == client
    assert secret.id == expected_id
    assert secret.created == "12345"
    assert secret.rsa_key_owner == rsa_key_owner_id
    assert secret.created_by == created_by_id
    assert secret.encryption_details.initialisation_vector == mock_crypto["iv"]
    assert secret.encryption_details.symmetric_key == mock_crypto["key"]


def test_create_secret_via_identity(client, api_client, key_store,
                                    private_key, mock_crypto):
    expected_id = str(uuid.uuid4())
    created_by_id = str(uuid.uuid4())

    api_client.get_identity.return_value = dict(
        version=1,
        id=created_by_id,
        externalId="1",
        cryptoPublicKey="crypto_public_key",
        metadata=dict(name="Bob"))
    key_store.get_private_encryption_key.return_value = private_key
    api_client.create_secret.return_value = dict(
        id=expected_id, href="https://test.com/v1/secret")

    api_client.get_secret.return_value = dict(
        id=expected_id,
        created="12345",
        rsaKeyOwner=created_by_id,
        createdBy=created_by_id,
        encryptionDetails=dict(
            initialisationVector=mock_crypto["iv"],
            symmetricKey=mock_crypto["key"]))

    identity = client.get_identity(created_by_id)

    secret = identity.create_secret("this is my secret".encode('utf-8'))

    assert secret.parent == client
    assert secret.id == expected_id
    assert secret.created == "12345"
    assert secret.rsa_key_owner == created_by_id
    assert secret.created_by == created_by_id
    assert secret.encryption_details.initialisation_vector == mock_crypto["iv"]
    assert secret.encryption_details.symmetric_key == mock_crypto["key"]


def test_share_secret(client, api_client, key_store, private_key, mock_crypto):
    secret_id = str(uuid.uuid4())
    shared_secret_id = str(uuid.uuid4())
    recipient_id = str(uuid.uuid4())
    created_by_id = str(uuid.uuid4())

    api_client.get_identity.return_value = dict(
        id=recipient_id, cryptoPublicKey="crypto_public_key")

    api_client.share_secret.return_value = dict(id=shared_secret_id)

    api_client.get_secret.return_value = dict(
        id=shared_secret_id,
        created="67890",
        rsaKeyOwner=recipient_id,
        createdBy=created_by_id,
        encryptionDetails=dict(
            initialisationVector=mock_crypto["iv"],
            symmetricKey=mock_crypto["key"]),
        baseSecretId=secret_id)

    api_client.get_secret_content.return_value = b64encode(b"my secret")

    key_store.get_private_encryption_key.return_value = private_key

    secret = client.share_secret(created_by_id, recipient_id, secret_id)

    assert secret.parent == client
    assert secret.id == shared_secret_id
    assert secret.created == "67890"
    assert secret.rsa_key_owner == recipient_id
    assert secret.created_by == created_by_id
    assert secret.encryption_details.initialisation_vector == mock_crypto["iv"]
    assert secret.encryption_details.symmetric_key == mock_crypto["key"]
    assert secret.base_secret_id == secret_id


@pytest.mark.parametrize("identity_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("secret_id", [None, str(uuid.uuid4())])
def test_delete_secret(client, api_client, identity_id, secret_id):
    client.delete_secret(identity_id, secret_id)
    api_client.delete_secret.assert_called_with(identity_id, secret_id)


@pytest.mark.parametrize("identity_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("secret_id", [None, str(uuid.uuid4())])
def test_get_secret_metadata(client, api_client, identity_id, secret_id):
    client.get_secret_metadata(identity_id, secret_id)
    api_client.get_secret_metadata.assert_called_with(identity_id, secret_id)


@pytest.mark.parametrize("identity_id", [str(uuid.uuid4())])
@pytest.mark.parametrize("secret_id", [str(uuid.uuid4())])
@pytest.mark.parametrize("metadata", [{"a": "b"}])
def test_add_secret_metadata(client, api_client, identity_id, secret_id,
                             metadata):
    existing = {"c": "d"}
    expected = existing.copy()
    expected.update(metadata)
    api_client.get_secret_metadata.return_value = existing, 1
    client.add_secret_metadata(identity_id, secret_id, metadata)
    api_client.update_secret_metadata.assert_called_with(
        identity_id,
        secret_id,
        expected,
        1)


@pytest.mark.parametrize("secret_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("rsa_key_owner_id", [None, str(uuid.uuid4())])
def test_get_events(client, api_client, secret_id, rsa_key_owner_id):
    identity_id = str(uuid.uuid4())
    inputs = {}
    if secret_id is not None:
        inputs["secret_id"] = secret_id
    if rsa_key_owner_id is not None:
        inputs["rsa_key_owner_id"] = rsa_key_owner_id

    expected_response_json = [{
        'eventDetails': {
            'baseSecretId': None,
            'requesterId': identity_id,
            'rsaKeyOwnerId': inputs.get(secret_id, str(uuid.uuid4())),
            'secretId': inputs.get(rsa_key_owner_id, str(uuid.uuid4())),
            'secretOwnerId': identity_id},
        'host': 'delta.covata.io',
        'id': '25b545e0-fe04-11e6-a09b-ff649a342cab',
        'sourceIp': '203.191.194.14',
        'timestamp': '2017-02-28T22:20:39.097Z',
        'type': 'access_success_event'}]
    api_client.get_events.return_value = expected_response_json
    response = list(client.get_events(identity_id, secret_id, rsa_key_owner_id))
    assert len(response) == len(expected_response_json)

    for r, expected in zip(response, expected_response_json):
        expected_event_details = EventDetails(
            base_secret_id=expected["eventDetails"]["baseSecretId"],
            requestor_id=expected["eventDetails"]["requesterId"],
            rsa_key_owner_id=expected["eventDetails"]["rsaKeyOwnerId"],
            secret_id=expected["eventDetails"]["secretId"],
            secret_owner_id=expected["eventDetails"]["secretOwnerId"]
        )
        assert r.event_details == expected_event_details
        assert r.host == expected["host"]
        assert r.id == expected["id"]
        assert r.source_ip == expected["sourceIp"]
        assert r.timestamp == datetime.strptime(
            expected["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        assert r.event_type == expected["type"]


def test_get_secrets(client, api_client):
    requestor_id = str(uuid.uuid4())
    rsa_key_owner_id = str(uuid.uuid4())
    base_secret_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())
    metadata = dict(key="value")
    expected_json_response = [
        {'baseSecret': base_secret_id,
         'created': '2017-03-02T00:04:24Z',
         'createdBy': requestor_id,
         'href': 'https://delta.covata.io/v1/secrets/{}'.format(secret_id),
         'id': secret_id,
         'metadata': metadata,
         'rsaKeyOwner': rsa_key_owner_id
         }]
    api_client.get_secrets.return_value = expected_json_response
    secrets = list(client.get_secrets(
        requestor_id, base_secret_id, requestor_id, rsa_key_owner_id, metadata,
        SecretLookupType.any, page=1, page_size=1))

    assert len(secrets) == len(expected_json_response)

    for secret, secret_json in zip(secrets, expected_json_response):
        assert secret.id == secret_json["id"]
        assert secret.base_secret_id == secret_json["baseSecret"]
        assert secret.created == secret_json["created"]
        assert secret.created_by == secret_json["createdBy"]
        assert secret.rsa_key_owner == secret_json["rsaKeyOwner"]
        assert secret.encryption_details == None

    api_client.get_secrets.assert_called_with(
        requestor_id, base_secret_id, requestor_id, rsa_key_owner_id, metadata,
        SecretLookupType.any, 1, 1)
