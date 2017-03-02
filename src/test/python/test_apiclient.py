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

import pytest
import requests
import responses
from six.moves import urllib

from covata.delta import ApiClient, SecretLookupType
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

    content = "123"
    key = "1234"
    iv = "1312"
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

    assert request_json["content"] == content
    assert encryption_details["symmetricKey"] == key
    assert encryption_details["initialisationVector"] == iv


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

    content = "123"
    key = "1234"
    iv = "1312"
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
    assert request_json["content"] == content
    assert encryption_details["symmetricKey"] == key
    assert encryption_details["initialisationVector"] == iv


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
    key = "12331"
    iv = "1242"

    response_json = dict(
        id=secret_id,
        created="2017-02-17T03:03:12Z",
        createdBy=requestor_id,
        href="https://delta.covata.io/v1/secrets/" + secret_id,
        rsaKeyOwner=requestor_id,
        encryptionDetails=dict(
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
    assert response == response_json


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
    expected_content = "123456"

    responses.add(
        responses.GET,
        "{base_path}{resource}/{secret_id}/content".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_SECRETS,
            secret_id=secret_id),
        expected_content)

    retrieved_content = api_client.get_secret_content(requestor_id, secret_id)
    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert retrieved_content == expected_content


@responses.activate
@pytest.mark.parametrize("page", [1, 3.0, "5", None])
@pytest.mark.parametrize("page_size", [1, "3", 5.0, None])
def test_get_identities_by_metadata_with_valid_page_parameters(
        api_client, mock_signer, page, page_size):
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
        page=page,
        page_size=page_size)

    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert response == expected_json
    url = urllib.parse.urlparse(responses.calls[0].request.url)
    query_params = dict(urllib.parse.parse_qsl(url.query))
    expected_query_params = {
        "metadata.name": "test123"
    }

    if page is not None:
        expected_query_params["page"] = str(int(page))

    if page_size is not None:
        expected_query_params["pageSize"] = str(int(page_size))

    assert query_params == expected_query_params


@responses.activate
@pytest.mark.parametrize("page", [0, -3.0, "-5"])
@pytest.mark.parametrize("page_size", [0, "-3", 5.0])
def test_get_identities_by_metadata__should__fail_when_page_is_invalid(
        api_client, mock_signer, page, page_size):
    requestor_id = "requestor_id"
    with pytest.raises(ValueError) as excinfo:
        api_client.get_identities_by_metadata(
            requestor_id=requestor_id,
            metadata=dict(name="test123"),
            page=page,
            page_size=page_size)
    mock_signer.assert_not_called()
    assert len(responses.calls) == 0
    assert "must be a non-zero positive integer" in str(excinfo.value)


@responses.activate
@pytest.mark.parametrize("metadata", [{}, None])
def test_get_identities_by_metadata__should__fail_when_metadata_is_empty(
        api_client, mock_signer, metadata):
    requestor_id = "requestor_id"
    with pytest.raises(ValueError) as excinfo:
        api_client.get_identities_by_metadata(
            requestor_id=requestor_id,
            metadata=metadata)
    mock_signer.assert_not_called()
    assert len(responses.calls) == 0
    assert "metadata must be a non-empty dict[str, str]" in str(excinfo.value)


@responses.activate
@pytest.mark.parametrize("secret_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("rsa_key_owner_id", [None, str(uuid.uuid4())])
def test_get_events(api_client, mock_signer, secret_id, rsa_key_owner_id):
    requestor_id = str(uuid.uuid4())
    expected_query_params = {
        "purpose": "AUDIT"
    }
    inputs = {}
    if secret_id is not None:
        inputs["secret_id"] = secret_id
        expected_query_params["secretId"] = secret_id
    if rsa_key_owner_id is not None:
        inputs["rsa_key_owner_id"] = rsa_key_owner_id
        expected_query_params["rsaKeyOwner"] = rsa_key_owner_id

    expected_json = [{
        'eventDetails': {
            'baseSecretId': None,
            'requesterId': requestor_id,
            'rsaKeyOwnerId': inputs.get(secret_id, str(uuid.uuid4())),
            'secretId': inputs.get(rsa_key_owner_id, str(uuid.uuid4())),
            'secretOwnerId': requestor_id},
        'host': 'delta.covata.io',
        'id': '25b545e0-fe04-11e6-a09b-ff649a342cab',
        'sourceIp': '203.191.194.14',
        'timestamp': '2017-02-28T22:20:39.097Z',
        'type': 'access_success_event'}]
    responses.add(
        responses.GET,
        "{base_path}{resource}".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_EVENTS),
        json=expected_json)
    response = api_client.get_events(requestor_id, secret_id, rsa_key_owner_id)

    assert response == expected_json
    mock_signer.assert_called_once_with(requestor_id)
    assert len(responses.calls) == 1

    url = urllib.parse.urlparse(responses.calls[0].request.url)
    query_params = dict(urllib.parse.parse_qsl(url.query))

    assert query_params == expected_query_params


@responses.activate
@pytest.mark.parametrize("requestor_id, secret_id, rsa_key_owner_id", [
    (None, str(uuid.uuid4()), str(uuid.uuid4())),
    ("", str(uuid.uuid4()), str(uuid.uuid4())),
    (str(uuid.uuid4()), None, ""),
    (str(uuid.uuid4()), str(uuid.uuid4()), ""),
    (str(uuid.uuid4()), "", None),
    (str(uuid.uuid4()), "", str(uuid.uuid4())),
    (str(uuid.uuid4()), "", ""),
])
def test_get_events__should__fail_when_id_is_an_empty_string(
        api_client, mock_signer, requestor_id, secret_id, rsa_key_owner_id):
    with pytest.raises(ValueError) as excinfo:
        api_client.get_events(requestor_id, secret_id, rsa_key_owner_id)
    mock_signer.assert_not_called()
    assert len(responses.calls) == 0
    assert "must be a nonempty string" in str(excinfo.value)


@responses.activate
@pytest.mark.parametrize(
    "requestor_id, base_secret_id, created_by, rsa_key_owner_id, metadata, "
    "lookup_type, page, page_size", [
        (None, None, None, None, None, SecretLookupType.any, None, None),
        ("1", "", None, None, None, SecretLookupType.any, None, None),
        ("1", "1", "", None, None, SecretLookupType.any, None, None),
        ("1", "1", "1", "", None, SecretLookupType.any, None, None),
        ("1", "1", "1", "1", {}, SecretLookupType.any, None, None),
        ("1", "1", "1", "1", {"a": "b"}, 1, None, None),
        ("1", "1", "1", "1", {"a": "b"}, "any", None, None),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, "", None),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, -1, None),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, "-1", None),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, 0, None),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, 1, ""),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, 1, "-1"),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, 1, -10),
        ("1", "1", "1", "1", {"a": "b"}, SecretLookupType.any, 1, 0),
])
def test_get_events__should__fail_on_invalid_parameter(
        api_client, mock_signer, requestor_id,
        base_secret_id, created_by, rsa_key_owner_id, metadata,
        lookup_type, page, page_size):
    with pytest.raises(ValueError):
        api_client.get_secrets(
            requestor_id=requestor_id,
            base_secret_id=base_secret_id,
            created_by=created_by,
            rsa_key_owner_id=rsa_key_owner_id,
            metadata=metadata,
            lookup_type=lookup_type,
            page=page,
            page_size=page_size)
    mock_signer.assert_not_called()
    assert len(responses.calls) == 0


@responses.activate
@pytest.mark.parametrize("base_secret_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("created_by", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("rsa_key_owner_id", [None, str(uuid.uuid4())])
@pytest.mark.parametrize("metadata", [None, dict(key="value")])
@pytest.mark.parametrize("lookup_type", [
    SecretLookupType.any, SecretLookupType.derived, SecretLookupType.base])
@pytest.mark.parametrize("page", [None, 1])
@pytest.mark.parametrize("page_size", [None, 1])
def test_get_secrets(api_client, mock_signer, base_secret_id, created_by,
                     rsa_key_owner_id, metadata, lookup_type, page, page_size):
    requestor_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())

    if lookup_type is SecretLookupType.derived \
            or lookup_type is SecretLookupType.any:
        base_secret_ = base_secret_id if base_secret_id is not None \
            else str(uuid.uuid4())
    else:
        base_secret_ = None

    expected_json = [
        {'baseSecret': base_secret_,
         'created': '2017-03-02T00:04:24Z',
         'createdBy': requestor_id if created_by is None else created_by,
         'href': 'https://delta.covata.io/v1/secrets/{}'.format(secret_id),
         'id': secret_id,
         'metadata': {} if metadata is None else dict(metadata),
         'rsaKeyOwner': str(uuid.uuid4()) if rsa_key_owner_id is None
            else rsa_key_owner_id
         }]
    responses.add(
        responses.GET,
        "{base_path}{resource}".format(
            base_path=ApiClient.DELTA_URL,
            resource=ApiClient.RESOURCE_SECRETS),
        json=expected_json)

    response = api_client.get_secrets(
        requestor_id=requestor_id,
        base_secret_id=base_secret_id,
        created_by=created_by,
        rsa_key_owner_id=rsa_key_owner_id,
        metadata=metadata,
        lookup_type=lookup_type,
        page=page,
        page_size=page_size)

    mock_signer.assert_called_once_with(requestor_id)

    assert len(responses.calls) == 1
    assert response == expected_json
    url = urllib.parse.urlparse(responses.calls[0].request.url)
    query_params = dict(urllib.parse.parse_qsl(url.query))

    expected_query_params = dict(
        page=str(page) if page else None,
        pageSize=str(page_size) if page_size else None,
        baseSecret=None if base_secret_id is None else str(base_secret_id),
        createdBy=None if created_by is None else str(created_by),
        rsaKeyOwner=None if rsa_key_owner_id is None else str(
            rsa_key_owner_id))

    if metadata is not None:
        metadata_ = dict(("metadata." + k, v) for k, v in metadata.items())
        expected_query_params.update(metadata_)

    if lookup_type is SecretLookupType.base:
        expected_query_params["baseSecret"] = "false"
    elif lookup_type is SecretLookupType.derived:
        expected_query_params["baseSecret"] = "true"

    expected_query_params = dict(
        (k, v) for k, v in expected_query_params.items() if v is not None)

    assert query_params == expected_query_params


def test_construct_signer(mocker, api_client, key_store, private_key):
    get_private_signing_key = mocker.patch.object(
        key_store, 'get_private_signing_key', return_value=private_key)
    signer = api_client.signer("mock_id")
    r = requests.Request(url='https://test.com/stage/resource',
                         method='POST',
                         headers=dict(someKey="some value"),
                         json=dict(content="abcd")) \
        .prepare()
    headers = dict(r.headers)
    get_updated_headers = mocker.patch(
        "covata.delta.signer.get_updated_headers",
        return_value=mocker.Mock())
    signer(r)
    get_private_signing_key.assert_called_once_with("mock_id")
    get_updated_headers.assert_called_once_with(
        identity_id="mock_id",
        method=r.method,
        url=r.url,
        headers=headers,
        payload=r.body,
        private_signing_key=private_key)
