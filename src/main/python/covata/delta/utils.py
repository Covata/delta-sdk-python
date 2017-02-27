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

import inspect
import functools


def check_arguments(arguments, validation_function, fail_message):
    def decorator(function):
        @functools.wraps(function)
        def _f(*args, **kwargs):
            keys, _, _, _ = inspect.getargspec(function)
            ins = dict(zip(keys, args))
            ins.update(kwargs)
            generator = ((x, y) for x, y in ins.items() if x in arguments)
            for arg, value in generator:
                if not validation_function(value):
                    raise ValueError("{} {}".format(arg, fail_message))
            return function(*args, **kwargs)
        return _f
    return decorator


def check_id(arguments):
    return check_arguments(arguments,
                           lambda x: x is not None and str(x) is not "",
                           "must be a nonempty string")
