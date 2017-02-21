# Covata Delta Python SDK
[![Build Status](https://travis-ci.org/Covata/delta-sdk-python.svg?branch=master)](https://travis-ci.org/Covata/delta-sdk-python)
[![Coverage Status](https://coveralls.io/repos/github/Covata/delta-sdk-python/badge.svg)](https://coveralls.io/github/Covata/delta-sdk-python)
[![Documentation Status](https://readthedocs.org/projects/delta-sdk-python/badge/?version=latest)](http://delta-sdk-python.readthedocs.io/en/latest/?badge=latest)

Covata Delta provides an easy to use framework for sharing secrets across networks, and organisations.

## Requirements

- Python 2.7 + or 3.3 +
- pip 9.0.1 +
- virtualenv: `sudo pip install virtualenv`
- pybuilder: `pip install pybuilder`

```bash
sudo pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install pybuilder 
```

## Quick Start

### Building the project

```bash
# 1. Check out the project
git clone https://github.com/Covata/delta-sdk-python.git
cd delta-sdk-python

# 2. Build the project
pyb
```

### Installing the binary distribution

* Using PyBuilder
```bash
pyb install
```

* Using Distutils
```bash
cd target/dist/delta-sdk-python-x.x.x-x
python setup.py install
```

* Using pip directly from Github
```bash
pip install git+git://github.com/Covata/delta-sdk-python.git@master
```

## License

Copyright 2017 Covata Limited or its affiliates - Released under the [Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
