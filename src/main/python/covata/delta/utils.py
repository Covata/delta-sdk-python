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

import logging
import inspect


class LogMixin:
    @property
    def logger(self):
        return logging.getLogger(caller())


def caller():
    """
    Gets the name of the caller in {package}.{module}.{class} format

    :return: the caller name
    :rtype: str
    """
    stack = inspect.stack()
    if len(stack) < 3:
        return ''

    caller_frame = stack[2][0]
    module = inspect.getmodule(caller_frame)

    name = filter(lambda x: x is not None, [
        module.__name__ if module else None,
        caller_frame.f_locals['self'].__class__.__name__
        if 'self' in caller_frame.f_locals else None])
    del caller_frame
    return ".".join(name)


def check_arguments(arguments, test_type, test_function, fail_message):
    def decorator(function):
        def _f(*args, **kwargs):
            for arg, value in kwargs.items():
                if arg in arguments:
                    if not any(value is t or isinstance(value, t)
                               for t in test_type):
                        raise TypeError(
                            "{arg} must be in {type}, actual {actual}".format(
                                arg=arg,
                                type=test_type,
                                actual=type(value).__name__))
                    if not test_function(value):
                        raise ValueError("{arg}:{msg} actual:{value}".format(
                            arg=arg,
                            msg=fail_message,
                            value=value))
            return function(*args, **kwargs)
        return _f
    return decorator
