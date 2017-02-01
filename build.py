"""
   Copyright 2016 Covata Limited or its affiliates

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from pybuilder.core import use_plugin, init

use_plugin("python.core")
use_plugin("python.unittest")
use_plugin("python.install_dependencies")
use_plugin("python.flake8")
use_plugin("python.coverage")
use_plugin("python.distutils")
use_plugin('python.pycharm')


name = "delta-sdk-python"
default_task = ['install_dependencies', 'publish']


@init
def set_properties(project):
    # Tests
    project.set_property("dir_source_unittest_python", "src/test/python")
    project.set_property("unittest_module_glob", "test_*")

    # Flake8
    project.set_property("flake8_include_test_sources", True)
    project.set_property("flake8_max_line_length", 80)
    project.set_property("flake8_verbose_output", True)
    project.set_property("flake8_break_build", True)

    # Project
    project.version = "0.0.1-alpha"
    project.depends_on_requirements("requirements.txt")
