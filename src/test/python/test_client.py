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


import pytest
import uuid

from covata.delta import Client
from covata.delta import ApiClient


@pytest.fixture(scope="function")
def client(api_client, key_store):
    return Client(dict(api_client=api_client,
                       key_store=key_store))


@pytest.fixture(scope="function")
def mock_signer(mocker, api_client):
    return mocker.patch.object(api_client, "signer",
                               return_value=mocker.Mock())


@pytest.fixture(scope="function")
def api_client(key_store):
    return ApiClient(key_store)


def test_create_identity(mocker, client, api_client, key_store, private_key,
                         key2bytes):
    expected_id = str(uuid.uuid4())

    mocker.patch('covata.delta.crypto.generate_private_key',
                 return_value=private_key)

    mocker.patch.object(api_client, "register_identity",
                        return_value=expected_id)

    identity = client.create_identity("1", {})

    crypto_key = key_store.get_private_encryption_key(identity.identity_id)
    signing_key = key_store.get_private_signing_key(identity.identity_id)

    assert identity.identity_id == expected_id
    assert identity.external_id == "1"
    assert identity.metadata == dict()
    assert key2bytes(crypto_key) == key2bytes(private_key)
    assert key2bytes(signing_key) == key2bytes(private_key)


def test_get_identity_same_target(mocker, client, api_client):
    expected_id = str(uuid.uuid4())

    mocker.patch.object(api_client, "get_identity",
                        return_value=dict(version=1,
                                          id=expected_id,
                                          externalId="1",
                                          cryptoPublicKey="crypto_public_key",
                                          metadata=dict(name="Bob")))

    identity = client.get_identity(expected_id)

    assert identity.parent == client
    assert identity.identity_id == expected_id
    assert identity.external_id == "1"
    assert identity.metadata == dict(name="Bob")
    assert identity.public_encryption_key == "crypto_public_key"


def test_get_identity_different_target(mocker, client, api_client):
    auth_id = str(uuid.uuid4())
    expected_id = str(uuid.uuid4())

    mocker.patch.object(api_client, "get_identity",
                        return_value=dict(version=1,
                                          id=expected_id,
                                          externalId="1",
                                          cryptoPublicKey="crypto_public_key",
                                          metadata=dict(name="Bob")))

    identity = client.get_identity(auth_id, expected_id)

    assert identity.parent == client
    assert identity.identity_id == expected_id
    assert identity.external_id == "1"
    assert identity.metadata == dict(name="Bob")
    assert identity.public_encryption_key == "crypto_public_key"

