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

import json
import re
from base64 import b64encode
from collections import OrderedDict
from datetime import datetime

import six.moves.urllib as urllib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from requests.auth import AuthBase
from collections import namedtuple

from covata.delta.util import LogMixin


class SignatureMaterial(namedtuple('SignatureMaterial', [
    'method',
    'uri',
    'query_params',
    'canonical_headers',
    'signed_headers',
    'hashed_payload'
])):
    def __init__(self, *args, **kwargs):
        super(SignatureMaterial, self).__init__()
        self.__canonical_request = "\n".join([
            self.method,
            self.uri,
            self.query_params,
            self.canonical_headers,
            self.signed_headers,
            self.hashed_payload])

    @property
    def canonical_request(self):
        return self.__canonical_request


class CVTSigner(AuthBase, LogMixin):
    UNDESIRED_HEADERS = ["Connection", "Content-Length"]
    SIGNING_ALGORITHM = "CVT1-RSA4096-SHA256"
    CVT_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

    def __init__(self, crypto_service, identity_id):
        """
        Create a Request Signer object to sign a ``Request`` object using
        the CVT1 request signing scheme.

        The :class:`~.CVTSigner` can be instantiated
        directly using its constructor:

        >>> signer = CVTSigner(crypto_service, authorizing_identity)

        The :class:`~.CVTSigner` can also be instantiated indirectly via a
        :class:`~.CryptoService` object by calling
        :func:`~covata.delta.crypto.CryptoService.signer`:

        >>> signer = crypto_service.signer(authorizing_identity)

        Example usage for getting an identity:

        >>> api_client = RequestsApiClient(crypto_service)
        >>> response = requests.get(
        ...     url="{base_url}{resource}{identity_id}".format(
        ...         base_url="https://delta.covata.io/v1",
        ...         resource="/identities/",
        ...         identity_id="e5fa4059-24c0-42a8-af9a-fe7280b43256"),
        ...     auth=self._crypto_service.signer(requestor_id))
        >>> print(response.json())


        :param crypto_service: The Crypto Service object
        :type crypto_service: :class:`~covata.delta.crypto.CryptoService`

        :param str identity_id: the authorizing identity id
        """
        self.__crypto_service = crypto_service
        self.__identity_id = identity_id
        self.__request_date = datetime.utcnow().strftime(self.CVT_DATE_FORMAT)

    def __call__(self, r):
        r.headers['Cvt-Date'] = self.__request_date
        r.headers['Host'] = urllib.parse.urlparse(r.url).hostname
        r.headers['Authorization'] = self.__get_auth_header(r)
        return r

    def __get_auth_header(self, request):
        signature_materials = self.__get_materials(request)
        canonical_request = signature_materials.canonical_request
        self.logger.debug(canonical_request)
        string_to_sign = "\n".join([
            self.SIGNING_ALGORITHM,
            self.__request_date,
            self.__crypto_service.sha256hex(canonical_request).decode('utf-8')])

        self.logger.debug(string_to_sign)
        signature = b64encode(self.__sign(string_to_sign)).decode('utf-8')

        auth_header = "{algorithm} Identity={identity_id}, " \
                      "SignedHeaders={signed_headers}, Signature={signature}" \
            .format(algorithm=self.SIGNING_ALGORITHM,
                    identity_id=self.__identity_id,
                    signed_headers=signature_materials.signed_headers,
                    signature=signature)

        self.logger.debug(auth_header)

        return auth_header

    def __sign(self, string_to_sign):
        private_key = self.__crypto_service.load(
            self.__identity_id + ".signing.pem")
        return private_key.sign(string_to_sign.encode("utf-8"),
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=32),
                                hashes.SHA256())

    def __get_hashed_payload(self, payload):
        sorted_payload = "{}" if payload is None else json.dumps(
            json.loads(payload), separators=(',', ':'), sort_keys=True)
        return self.__crypto_service.sha256hex(sorted_payload).decode('utf-8')

    def __get_materials(self, request):
        # type: (PreparedRequest) -> SignatureMaterial
        """
        prepare the signature materials needed

        :param request: the prepared request by
        :return: the SignatureMaterial named tuple
        :rtype: :class: `SignatureMaterial`
        """
        # /master/identities/a123?key=an+arbitrary+value&key2=x
        path = request.path_url.split("?")
        uri = self.__encode_uri("/".join(path[0].split("/")[2:]))
        query = path[1].replace("+", "%20") if len(path) == 2 else ""

        sorted_header = OrderedDict(sorted(
            (k.lower(), re.sub("\s+", ' ', v).strip())
            for k, v in request.headers.items()
            if k not in self.UNDESIRED_HEADERS))

        canonical_headers = "\n ".join(
            "{}:{}".format(k, v) for (k, v) in sorted_header.items())

        signed_headers = ";".join(sorted_header.keys())
        hashed_payload = self.__get_hashed_payload(request.body)

        return SignatureMaterial(method=request.method,
                                 uri=uri,
                                 query_params=query,
                                 canonical_headers=canonical_headers,
                                 signed_headers=signed_headers,
                                 hashed_payload=hashed_payload)

    @staticmethod
    def __encode_uri(resource_path):
        # type: (str) -> str
        if resource_path is not "/":
            uri_parsed = re.sub("^/+|/+$", "", resource_path)
            quoted_uri = urllib.parse.quote(uri_parsed).replace("%7E", "~")
            return "/{}/".format(quoted_uri)
        else:
            return resource_path
