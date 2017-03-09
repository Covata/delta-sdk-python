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

Example Usage
=============

These examples assume a folder called ``~/keystore`` is present with
``passPhrase`` as the password. Each example code-snippet is self-contained
and runnable.

Initialisation
--------------
- Initialising SDK Client (Configuration via Parameters)

.. code:: python

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)


Identity
--------

- Create an identity
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   client.create_identity()

- Get your own identity
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")

- Get a different identity
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                                  "1cb9375f-329c-405a-9b0c-b1659d9c66a4")

- Add metadata to an identity


Secret
------

-  Create a base secret
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   # option 1: via identity object
   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")
   secret = identity.create_secret("here is my secret")

   # option 2: via client object
   secret = client.create_secret("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                                 "here is my secret")

-  Create a base secret with metadata
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   metadata = {"reference number": "e3fc50a88d0a364313df4b21ef20c29e"}

   # option 1: via identity object
   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")
   secret = identity.create_secret("here is my secret", metadata)

   # option 2: via client object
   secret = client.create_secret("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                                 "here is my secret", metadata)

-  Get a base secret and the contents
.. code:: python

   from covata import delta

   key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
   client = Client(key_store)

   # option 1: via identity object
   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")
   secret = identity.get_secret("a9724dd3-8fa1-4ecd-bbda-331748410cf8")

   # option 2: via client object
   secret = client.get_secret("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                              "a9724dd3-8fa1-4ecd-bbda-331748410cf8")

    # it's all the same secret
    content = secret.get_content()
    reference = secret.get_metadata("reference number")


-  Delete a secret
.. code:: python

   from covata import delta

   # option 1: via secret object
   identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")
   identity.delete_secret("a9724dd3-8fa1-4ecd-bbda-331748410cf8")

   # option 2: via client object
   secret = client.delete_secret("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                                 "cb684cfe-11d1-47da-8433-436ca5e6efb0",
                                 "506542dd-161f-46b0-825d-364b0b19bc70")