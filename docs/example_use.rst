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
- Initialising the client

.. literalinclude:: ../examples/snippets/initialising_the_client.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 3-4

Identity
--------

- Creating an identity

.. literalinclude:: ../examples/snippets/creating_an_identity.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 6

- Getting your own identity

.. literalinclude:: ../examples/snippets/getting_your_own_identity.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 6

- Getting a different identity

.. literalinclude:: ../examples/snippets/getting_a_different_identity.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 6-7

Secret
------

-  Creating a base secret

.. literalinclude:: ../examples/snippets/creating_a_base_secret.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 8, 11-12

-  Getting a base secret and the contents

.. literalinclude:: ../examples/snippets/getting_a_base_secret_and_the_contents.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 8, 11-12, 15

-  Deleting a secret

.. literalinclude:: ../examples/snippets/deleting_a_secret.py
   :language: python
   :lines: 15-
   :linenos:
   :emphasize-lines: 8, 11-13
