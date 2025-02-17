# Python setup file
# Copyright (c) 2019 Robert Bosch GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from setuptools import Extension
from setuptools import setup

setup(
    ext_modules=[
        Extension(
            '_pylibfuzzer',
            ['src/CGIFuzz/fuzz_wrappers/libfuzzer/pylibfuzzer.c'],
            py_limited_api=True,
            define_macros=[('Py_LIMITED_API', None)],
        ),
    ],
)
