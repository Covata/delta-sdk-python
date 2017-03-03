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
from covata.delta import Identity
from covata.delta import Secret
from covata.delta import EncryptionDetails


@pytest.fixture(scope="function")
def client(mocker):
    return mocker.MagicMock()


@pytest.fixture(scope="function")
def identity_a(client):
    return Identity(parent=client,
                    id="id-a",
                    public_encryption_key="key-a",
                    external_id="ext-a",
                    metadata=dict(name="a"))


@pytest.fixture(scope="function")
def identity_b(client):
    return Identity(parent=client,
                    id="id-b",
                    public_encryption_key="key-b",
                    external_id="ext-b",
                    metadata=dict(name="b"))


@pytest.fixture(scope="function")
def secret(client):
    return Secret(client,
                  id="id-1",
                  created="123",
                  rsa_key_owner="id-a",
                  created_by="id-a",
                  encryption_details=EncryptionDetails(
                      symmetric_key="sym-a",
                      initialisation_vector="iv-a"
                  ))


def test_get_content(secret, client):
    secret.get_content()
    client.get_secret_content.assert_called_with(
        secret.created_by,
        secret.id,
        secret.encryption_details.symmetric_key,
        secret.encryption_details.initialisation_vector)


def test_share_with(secret, identity_b, client):
    secret.share_with(identity_b.id)
    client.share_secret.assert_called_with(secret.created_by,
                                           identity_b.id,
                                           secret.id)


def test_get_metadata(secret, client):
    client.get_secret_metadata.return_value = {}, 1
    secret.get_metadata()
    client.get_secret_metadata.assert_called_with(secret.created_by, secret.id)


@pytest.mark.parametrize("rsa_key_owner_id", [None, "rsa-key-owner-id"])
def test_get_events(secret, rsa_key_owner_id, client):
    secret.get_events(rsa_key_owner_id)
    client.get_events.assert_called_with(secret.created_by,
                                         secret.id,
                                         rsa_key_owner_id)


@pytest.mark.parametrize("page", [None, 1])
@pytest.mark.parametrize("page_size", [None, 1])
def test_get_derived_secret(secret, client, page, page_size):
    secret.get_derived_secrets(page, page_size)
    client.get_secrets.assert_called_with(
        requestor_id=secret.created_by,
        base_secret_id=secret.id,
        page=page,
        page_size=page_size)


def test_repr(secret):
    assert str(secret) == "Secret(id={})".format(secret.id)
