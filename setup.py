#!/usr/bin/python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup

version = "1.5.6"

setup(name="IM-client", version=version,
      author='GRyCAP - Universitat Politecnica de Valencia',
      author_email='micafer1@upv.es',
      url='http://www.grycap.upv.es/im',
      packages=[''],
      package_dir={'': '.'},
      scripts=["im_client.py"],
      package_data={"": ["LICENSE", "INSTALL", "NOTICE", "auth.dat"]},
      license="GPL version 3, http://www.gnu.org/licenses/gpl-3.0.txt",
      long_description=open('README.md').read(),
      long_description_content_type='text/markdown',
      description="IM is a tool to manage virtual infrastructures on Cloud deployments",
      platforms=["any"],
      install_requires=["radl", "netaddr", "requests"]
      )
