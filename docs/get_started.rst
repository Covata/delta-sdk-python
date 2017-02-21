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

Quick Start
===========

Requirements
------------

-  Python 2.7 + or 3.3 +
-  pip 9.0.1 +
-  virtualenv: ``sudo pip install virtualenv``
-  pybuilder: ``pip install pybuilder``

.. code:: bash

    sudo pip install virtualenv
    virtualenv venv
    source venv/bin/activate
    pip install pybuilder

Building the project
--------------------

.. code:: bash

    # 1. Check out the project
    git clone https://github.com/Covata/delta-sdk-python.git
    cd delta-sdk-python

    # 2. Build the project
    pyb

Installing the binary distribution
----------------------------------

-  Using PyBuilder

   .. code:: bash

       pyb install

-  Using Distutils

   .. code:: bash

       cd target/dist/delta-sdk-python-x.x.x-x
       python setup.py install

-  Using pip directly from Github

   .. code:: bash

       pip install git+git://github.com/Covata/delta-sdk-python.git@master
