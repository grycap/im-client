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

import os

class Authentication:

	def __init__(self, auth_data):
		if isinstance(auth_data, Authentication):
			self.auth_list = auth_data.auth_list
		else:
			self.auth_list = auth_data
		
	def getAuthInfo(self, type, host = None):
		res = []
		for auth in self.auth_list:
			if auth['type'] == type:
				res.append(auth)
		return res
	
	def getAuthInfoByID(self, id):
		res = []
		for auth in self.auth_list:
			if auth['id'] == id:
				res.append(auth)
		return res


	def compare(self, other_auth, type):
		try:
			auth_with_type = None
			for auth in self.auth_list:
				if auth['type'] == type:
					auth_with_type = auth
			
			other_auth_with_type = None	
			for auth in other_auth.auth_list:
				if auth['type'] == type:
					other_auth_with_type = auth
					
			if auth_with_type != None and other_auth_with_type != None:
				if len(auth_with_type) != len(other_auth_with_type):
					return False
				
				for key in auth_with_type.keys():
					if auth_with_type[key] != other_auth_with_type[key]:
						return False
			else:
				return False

		except Exception, ex:
			return False
		
		return True

	@staticmethod
	def read_auth_data(filename):
		if isinstance(filename, list):
			lines = filename
		else:
			auth_file = open(filename, 'r')
			lines = auth_file.readlines()
			auth_file.close()
	
		res = []
		i = 0
		for line in lines:
			line = line.strip()
			if len(line) > 0 and not line.startswith("#"):
				auth = {}
				tokens = line.split(";")
				for token in tokens:
					key_value = token.split(" = ")
					if len(key_value) != 2:
						break;
					else:
						auth[key_value[0].strip()] = key_value[1].strip().replace("\\n","\n")
				res.append(auth)
		
		return res
