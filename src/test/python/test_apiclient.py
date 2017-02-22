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

import json
import uuid
from base64 import b64decode, b64encode

import pytest
import requests
import responses
from six.moves import urllib

from covata.delta import ApiClient
from covata.delta import crypto


@pytest.fixture(scope="function")
def mock_signer(mocker, api_client):
    return mocker.patch.object(api_client, "signer",
                               return_value=mocker.Mock())


@pytest.fixture(scope="function")
def api_client(key_store):
    return ApiClient(key_store)


@responses.activate
def test_register_identity(mocker, api_client, private_key):
    public_key = private_key.public_key()
    expected_id = "identity_id"
    responses.add(responses.POST,
                  ApiClient.DELTA_URL + ApiClient.RESOURCE_IDENTITIES,
                  status=201,
                  json=dict(identityId=expected_id))

    mocker.patch('covata.delta.crypto.generate_private_key',
                 return_value=private_key)

    public_signing_key = crypto.serialize_public_key(public_key)
    public_encryption_key = crypto.serialize_public_key(public_key)

    identity_id = api_client.register_identity(public_encryption_key,
                                               public_signing_key, "1", {})

    assert len(responses.calls) == 1
    assert identity_id == expected_id

    request_body = json.loads(responses.calls[0].request.body.decode("utf-8"))
    expected_request_body = dict(
        externalId="1",
        metadata=dict(),
        cryptoPublicKey=public_encryption_key,
        signingPublicKey=public_signing_key
    )

    assert request_body == expected_request_body


@responses.activate
def test_get_identity(api_client, mock_signer):
    expected_id = str(uuid.uuid4())
    expected_json = dict(version=1,
                         id=expected_id,
                         cryptoPublicKey="crypto_public_key",
                         metadata=dict(name="Bob"))

    responses.add(responses.GET,
                  "{base_path}{resource}/{identity_id}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_IDENTITIES,
                      identity_id=expected_id),
                  status=200,
                  json=expected_json)

    response = api_client.get_identity(requestor_id="requestor_id",
                                       identity_id=expected_id)

    mock_signer.assert_called_once_with("requestor_id")

    assert len(responses.calls) == 1
    assert response == expected_json


@responses.activate
def test_create_secret(api_client, mock_signer):
    expected_json = dict(id="mock_secret_id",
                         href="https://test.com/v1/mock_secret_id")

    responses.add(responses.POST,
                  "{base_path}{resource}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_SECRETS),
                  status=201,
                  json=expected_json)

    content = b"123"
    key = b"1234"
    iv = b"1312"
    response = api_client.create_secret(
        requestor_id="requestor_id",
        content=content,
        encryption_details=dict(
            symmetricKey=key,
            initialisationVector=iv))

    mock_signer.assert_called_once_with("requestor_id")

    assert len(responses.calls) == 1
    assert response == expected_json

    request_json = json.loads(responses.calls[0].request.body.decode("utf-8"))
    encryption_details = request_json["encryptionDetails"]

    assert b64decode(request_json["content"]) == content
    assert b64decode(encryption_details["symmetricKey"]) == key
    assert b64decode(encryption_details["initialisationVector"]) == iv


@responses.activate
def test_share_secret(api_client, mock_signer):
    expected_json = dict(id="mock_secret_id",
                         href="https://test.com/v1/mock_secret_id")

    responses.add(responses.POST,
                  "{base_path}{resource}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_SECRETS),
                  status=201,
                  json=expected_json)

    content = b"123"
    key = b"1234"
    iv = b"1312"
    rsa_key_owner_id = "rsa_key_owner_id"
    base_secret_id = "base"
    response = api_client.share_secret(
        requestor_id="requestor_id",
        content=content,
        encryption_details=dict(
            symmetricKey=key,
            initialisationVector=iv),
        rsa_key_owner_id=rsa_key_owner_id,
        base_secret_id=base_secret_id)

    mock_signer.assert_called_once_with("requestor_id")

    assert len(responses.calls) == 1
    assert response == expected_json

    request_json = json.loads(responses.calls[0].request.body.decode("utf-8"))
    encryption_details = request_json["encryptionDetails"]

    assert request_json["rsaKeyOwner"] == rsa_key_owner_id
    assert request_json["baseSecret"] == base_secret_id
    assert b64decode(request_json["content"]) == content
    assert b64decode(encryption_details["symmetricKey"]) == key
    assert b64decode(encryption_details["initialisationVector"]) == iv


@responses.activate
def test_update_secret_metadata(api_client, mock_signer):
    responses.add(responses.PUT,
                  "{base_path}{resource}/{secret_id}/metadata".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_SECRETS,
                      secret_id="mock_id"),
                  status=204)

    metadata = dict(metadata_key="metadata value")
    api_client.update_secret_metadata(requestor_id="requestor_id",
                                      secret_id="mock_id",
                                      metadata=metadata,
                                      version=1)

    mock_signer.assert_called_once_with("requestor_id")

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers["if-match"] == str(1)

    request_json = json.loads(responses.calls[0].request.body.decode("utf-8"))
    assert request_json == metadata


@responses.activate
def test_update_identity_metadata(api_client, mock_signer):
    responses.add(responses.PUT,
                  "{base_path}{resource}/{identity_id}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_IDENTITIES,
                      identity_id="mock_id"),
                  status=204)

    metadata = dict(metadata_key="metadata value")
    api_client.update_identity_metadata(requestor_id="requestor_id",
                                        identity_id="mock_id",
                                        metadata=metadata,
                                        version=1)

    mock_signer.assert_called_once_with("requestor_id")

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers["if-match"] == str(1)

    request_json = json.loads(responses.calls[0].request.body.decode("utf-8"))
    assert request_json["metadata"] == metadata


@responses.activate
def test_get_secret(api_client, mock_signer):
    requestor_id = "requestor_id"
    secret_id = "secret_id"
    key = b"12331"
    iv = b"1242"

    response_json = dict(
        id=secret_id,
        created="2017-02-17T03:03:12Z",
        createdBy=requestor_id,
        href="https://delta.covata.io/v1/secrets/" + secret_id,
        rsaKeyOwner=requestor_id,
        encryptionDetails=dict(
            symmetricKey=b64encode(key).decode("utf-8"),
            initialisationVector=b64encode(iv).decode("utf-8")
        ))

    expected_json = dict(response_json, encryptionDetails=dict(
        symmetricKey=key,
        initialisationVector=iv
    ))

    responses.add(responses.GET,
                  "{base_path}{resource}/{secret_id}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_SECRETS,
                      secret_id=secret_id),
                  status=200,
                  json=response_json)

    response = api_client.get_secret(requestor_id, secret_id)

    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert response == expected_json


@responses.activate
def test_delete_secret(api_client, mock_signer):
    requestor_id = "requestor_id"
    secret_id = "secret_id"

    responses.add(responses.DELETE,
                  "{base_path}{resource}/{secret_id}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_SECRETS,
                      secret_id=secret_id),
                  status=204)

    api_client.delete_secret(requestor_id, secret_id)

    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1


@responses.activate
def test_get_secret_metadata(api_client, mock_signer):
    response_json = dict(metadata_key="metadata value")
    requestor_id = "requestor_id"
    secret_id = "secret_id"
    expected_version = 1

    def request_callback(request):
        resp_body = response_json
        headers = {'etag': str(expected_version)}
        return 200, headers, json.dumps(resp_body)

    responses.add_callback(
        responses.GET,
        "{base_path}{resource}/{secret_id}/metadata".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_SECRETS,
            secret_id=secret_id),
        callback=request_callback,
        content_type='application/json')

    metadata, version = api_client.get_secret_metadata(requestor_id, secret_id)
    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert metadata == response_json
    assert version == expected_version


@responses.activate
def test_get_secret_content(api_client, mock_signer):
    requestor_id = "requestor_id"
    secret_id = "secret_id"
    expected_content = b"123456"

    responses.add(
        responses.GET,
        "{base_path}{resource}/{secret_id}/content".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_SECRETS,
            secret_id=secret_id),
        json=b64encode(expected_content).decode("utf-8"))

    retrieved_content = api_client.get_secret_content(requestor_id, secret_id)
    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert retrieved_content == expected_content


@responses.activate
def test_get_identities_by_metadata(api_client, mock_signer):
    requestor_id = "requestor_id"
    expected_json = [dict(cryptoPublicKey="cryptoPublicKey",
                          id="1",
                          metadata=dict(name="test123"),
                          version=2)]
    responses.add(
        responses.GET,
        "{base_path}{resource}".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_IDENTITIES),
        json=expected_json)

    response = api_client.get_identities_by_metadata(
        requestor_id=requestor_id,
        metadata=dict(name="test123"),
        page=1,
        page_size=3)

    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert response == expected_json
    url = urllib.parse.urlparse(responses.calls[0].request.url)
    query_params = dict(urllib.parse.parse_qsl(url.query))
    expected_query_params = {
        "metadata.name": "test123",
        "page": "1",
        "pageSize": "3"
    }
    assert query_params == expected_query_params


def test_construct_signer(mocker, api_client, key_store, private_key):
    get_private_signing_key = mocker.patch.object(
        key_store, 'get_private_signing_key', return_value=private_key)
    signer = api_client.signer("mock_id")

    r = requests.Request(url='https://test.com/stage/resource',
                         method='POST',
                         headers=dict(someKey="some value"),
                         json=dict(content="abcd"))
    signer(r.prepare())
    get_private_signing_key.assert_called_once_with("mock_id")
