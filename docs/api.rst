.. Copyright 2017 Covata Limited or its affiliates

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

API
====

The `covata.delta.api` module provides a set of tools for executing REST
calls to Delta API.

DeltaApiClient
--------------

The Delta API Client is an abstraction over the Delta API for execution of
requests and responses.

.. currentmodule:: covata.delta

.. autoclass:: DeltaApiClient
   :members:

.. currentmodule:: covata.delta.api

Requests ApiClient
~~~~~~~~~~~~~~~~~~

An implementation of ``DeltaApiClient`` abstract base class using ``Requests``.

.. autoclass:: RequestsApiClient
   :show-inheritance:
   :members:

CVTSigner
---------

The Delta CVT Signer is utility class for signing outbound requests using
the CVT1 signing scheme.

.. autoclass:: CVTSigner
   :members:

RequestsCVTSigner
~~~~~~~~~~~~~~~~~

An authentication interceptor for ``Requests`` library.
This interceptor generates and inserts an Authorization header into the
request based on the CVT1 signing scheme. A date header will also be added
to the request.

.. autoclass:: RequestsCVTSigner
   :show-inheritance:
   :members:
