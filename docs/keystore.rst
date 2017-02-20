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


KeyStore
========

The ``DeltaKeyStore`` provides the interface for a key-storage
backend of choice.

.. currentmodule:: covata.delta.keystore

.. autoclass:: DeltaKeyStore
    :members:

File-System KeyStore
--------------------

Implementation of the ``DeltaKeyStore`` abstract base class using the file
system. Private keys are saved in the file system as encrypted PEM formats
and are only decrypted in memory on read.

.. currentmodule:: covata.delta.keystore

.. autoclass:: FileSystemKeyStore
    :show-inheritance:
    :members: