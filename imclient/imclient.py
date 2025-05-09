#! /usr/bin/env python
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

try:
    # To avoid annoying InsecureRequestWarning messages in some Connectors
    import requests.packages
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass

import json
import os
import subprocess
import tempfile
import time
from optparse import OptionParser, Option, IndentedHelpFormatter, Values
from xmlrpc.client import ServerProxy

from radl import radl_parse


class PosOptionParser(OptionParser):
    """
    Class to add Help to operations
    """
    def format_help(self, formatter=None):
        """
        Format help
        """
        class Positional(object):
            """
            Positional argument
            """
            def __init__(self, arguments):
                self.option_groups = []
                self.option_list = arguments

        positional = Positional(self.positional)
        formatter = IndentedHelpFormatter()
        formatter.store_option_strings(positional)
        output = ['\n', formatter.format_heading("Operation")]
        formatter.indent()
        pos_help = [formatter.format_option(opt) for opt in self.positional]
        pos_help = [line.replace('--', '') for line in pos_help]
        output += pos_help
        return OptionParser.format_help(self, formatter) + ''.join(output)

    def add_operation_help(self, arg, helpstr):
        """
        Add operation help
        """
        try:
            arguments = self.positional
        except AttributeError:
            arguments = []
        arguments.append(Option('--' + arg, action='store_true', help=helpstr))
        self.positional = arguments

    def set_out(self, out):
        """
        Set out param
        """
        self.out = out


class CmdSsh:
    """
    Class to execute a ssh directly to a VM (from EC3)
    """

    @staticmethod
    def run(radl, show_only=False, cmd=None):
        try:
            if radl.systems[0].getValue("disk.0.os.credentials.private_key"):
                ops = CmdSsh._connect_key(radl)
            else:
                ops = CmdSsh._connect_password(radl)

            if cmd:
                if isinstance(cmd, list):
                    ops.extend(cmd)
                else:
                    ops.append(cmd)

            if show_only:
                for op in ops:
                    if "ProxyCommand" in op:
                        op = "'" + op + "'"
                    print(op, end=" ")
            else:
                os.execlp(ops[0], *ops)
        except OSError as e:
            raise Exception("Error connecting to VM: %s\nProbably 'sshpass' or 'ssh' "
                            "programs are not installed!" % str(e))
        except Exception as e:
            raise Exception("Error connecting to VM: %s" % str(e))

    @staticmethod
    def _get_ssh_port(radl):
        """
        Get the SSH port from the RADL

        Returns: str with the port
        """
        ssh_port = 22

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        if public_net:
            outports = public_net.getOutPorts() if public_net.getOutPorts() else {}
            for outport in outports:
                if outport.get_local_port() == 22 and outport.get_protocol() == "tcp":
                    ssh_port = outport.get_remote_port()

        return str(ssh_port)

    @staticmethod
    def get_user_pass_host_port(url):
        """
        Returns a tuple parsing values for this kind of urls:
        username:pass@servername.com:port
        """
        username = None
        password = None
        port = None
        if "@" in url:
            parts = url.split("@")
            user_pass = parts[0]
            server_port = parts[1]
            user_pass = user_pass.split(':')
            username = user_pass[0]
            if len(user_pass) > 1:
                password = user_pass[1]
        else:
            server_port = url

        server_port = server_port.split(':')
        server = server_port[0]
        if len(server_port) > 1:
            port = int(server_port[1])

        return username, password, server, port

    @staticmethod
    def _get_proxy_host(radl):
        """
        Return the proxy_host data if available
        """
        for netid in radl.systems[0].getNetworkIDs():
            net = radl.get_network_by_id(netid)
            if net.getValue("proxy_host"):
                user, passwd, ip, port = CmdSsh.get_user_pass_host_port(net.getValue("proxy_host"))
                if not port:
                    port = 22
                return ip, user, passwd, net.getValue("proxy_key"), port
        return None

    @staticmethod
    def _get_proxy_command(radl, ip, username):
        ssh_args = None
        if CmdSsh._get_proxy_host(radl):
            proxy_ip, proxy_user, proxy_pass, proxy_key, proxy_port = CmdSsh._get_proxy_host(radl)
            if proxy_key:
                # we assume that IM has copied it to the proxy host
                proxy_key_filename = "/var/tmp/%s_%s_%s.pem" % (proxy_user, username, ip)
                proxy_command = "ssh -W %%h:%%p -i %s -p %d %s %s@%s" % (proxy_key_filename,
                                                                         proxy_port,
                                                                         "-o StrictHostKeyChecking=no",
                                                                         proxy_user,
                                                                         proxy_ip)
            else:
                proxy_command = "sshpass -p %s ssh -W %%h:%%p -p %d %s %s@%s" % (proxy_pass,
                                                                                 proxy_port,
                                                                                 "-o StrictHostKeyChecking=no",
                                                                                 proxy_user,
                                                                                 proxy_ip)
            ssh_args = ["-o", "ProxyCommand=%s" % proxy_command]

        return ssh_args

    @staticmethod
    def _connect_password(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        ip = radl.getPublicIP()
        ssh_args = None
        if not ip:
            ip = radl.getPrivateIP()
            ssh_args = CmdSsh._get_proxy_command(radl, ip, s.getValue("disk.0.os.credentials.username"))

        res = ["sshpass", "-p%s" % s.getValue("disk.0.os.credentials.password"),
               "ssh", "-p", ssh_port, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]

        if ssh_args:
            res.extend(ssh_args)

        res.append("%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip))

        return res

    @staticmethod
    def _connect_key(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(s.getValue("disk.0.os.credentials.private_key"))
        f.close()

        ip = radl.getPublicIP()
        ssh_args = None
        if not ip:
            ip = radl.getPrivateIP()
            ssh_args = CmdSsh._get_proxy_command(radl, ip, s.getValue("disk.0.os.credentials.username"))

        res = ["ssh", "-p", ssh_port, "-i", f.name, "-o", "UserKnownHostsFile=/dev/null",
               "-o", "StrictHostKeyChecking=no"]
        if ssh_args:
            res.extend(ssh_args)
        res.append("%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip))

        return res


class CmdScp():
    """
    Class to execute a scp directly to a VM (from EC3)
    """

    @staticmethod
    def run(radl, op, cmd, show_only=False):
        try:
            if radl.systems[0].getValue("disk.0.os.credentials.private_key"):
                ops = CmdSsh._connect_key(radl)
            else:
                ops = CmdSsh._connect_password(radl)

            pos = ops.index("ssh")
            ops[pos] = "scp"
            ops.insert(pos + 1, "-r")
            pos = ops.index("-p", pos)
            ops[pos] = "-P"

            if op == "put":
                ops[-1] += f":{cmd[1]}"
                ops.insert(-1, cmd[0])
            elif op == "get":
                ops[-1] += f":{cmd[0]}"
                ops.append(cmd[1])
            else:
                raise Exception("Invalid operation: %s" % op)

            if show_only:
                for op in ops:
                    if "ProxyCommand" in op:
                        op = "'" + op + "'"
                    print(op, end=" ")
            else:
                os.execlp(ops[0], *ops)
        except OSError as e:
            raise Exception("Error connecting to VM: %s\nProbably 'sshpass' or 'ssh' "
                            "programs are not installed!" % str(e))
        except Exception as e:
            raise Exception("Error connecting to VM: %s" % str(e))


class IMClient:
    """
    Class to connect with the Infrastructure Manager
    """

    def __init__(self, options, auth_data, args):
        self.args = args
        self.server = None
        self.rest_auth_data = ""
        self.options = options
        self.auth_data = auth_data
        if options.restapi and auth_data:
            if isinstance(auth_data, str):
                self.rest_auth_data = auth_data
            else:
                for item in auth_data:
                    for key, value in item.items():
                        value = value.replace("\n", "\\\\n")
                        self.rest_auth_data += "%s = %s;" % (key, value)
                    self.rest_auth_data += "\\n"

        elif options.xmlrpc:
            if options.xmlrpc.startswith("https") and not options.verify:
                try:
                    import ssl
                    ssl._create_default_https_context = ssl._create_unverified_context
                except Exception:
                    pass
            self.server = ServerProxy(options.xmlrpc, allow_none=True)

    @staticmethod
    def init_client(im_url, auth_data, rest=True, ssl_verify=False):
        """
        Create and initialize the IMClient class
        Arguments:
           - im_url(string): URL to the IM API (REST or XML-RPC)
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider
                                                         (as returned by `read_auth_data` function).
           - rest(boolean): Flag to specify the type of API to use (REST or XML-RPC).
                            Default `True`.
           - ssl_verify(boolean): Flag to specify if ssl certificates must be validated.
                                  Default `False`.
        Returns(:py:class:`imclient.IMClient`): A client ready to interact with an IM instance.
        """
        options = {"force": False, "quiet": True, "name": None, "system_name": None}
        if rest:
            options["restapi"] = im_url
        else:
            options["xmlrpc"] = im_url
        options["verify"] = ssl_verify
        return IMClient(Values(options), auth_data, [])

    @staticmethod
    def _replace_auth_values(value):
        # Enable to specify a commnad and set the contents of the output
        if value.startswith("command(") and value.endswith(")"):
            command = value[8:-1]
            return "'%s'" % IMClient._run_command(command)
        # Enable to specify a filename and set the contents of it
        elif value.startswith("file(") and value.endswith(")"):
            try:
                with open(value[5:-1], 'r') as f:
                    data = f.read()
                return "'%s'" % data.strip()
            except Exception:
                pass
        return value

    @staticmethod
    def _split_line(line, separator=";", maintain_quotes=False):
        """
        Split line using ; as separator char
        considering single quotes as a way to delimit
        tokens. (in particular to enable using char ; inside a token)
        """
        tokens = []
        token = ""
        in_qoutes = False
        in_dqoutes = False
        has_quotes = False
        for char in line:
            if char == '"' and not in_qoutes:
                has_quotes = True
                in_dqoutes = not in_dqoutes
                if maintain_quotes:
                    token += char
            elif char == "'" and not in_dqoutes:
                has_quotes = True
                in_qoutes = not in_qoutes
                if maintain_quotes:
                    token += char
            elif char == separator and not in_qoutes and not in_dqoutes:
                tokens.append(token)
                token = ""
            else:
                token += char
        # Add the last token
        if token.strip() != "" or has_quotes:
            tokens.append(token)

        return tokens

    # From IM.auth
    @staticmethod
    def read_auth_data(filename):
        """
        Read an IM auth data file.
        Arguments:
           - filename(string): path to the IM auth file.
        Returns(:py:class:`list` of `dict` of str objects): Authentication data to access cloud provider and the IM.
        One entry per line, each line splitted in a dictionary of pairs key/value.
        """
        if isinstance(filename, list):
            lines = filename
        else:
            auth_file = open(filename, 'r')
            lines = auth_file.readlines()
            auth_file.close()

        res = []

        if len(lines) == 1 and lines[0].startswith("Bearer "):
            token = lines[0].strip()[7:]
            return "Bearer %s" % IMClient._replace_auth_values(token)

        for line in lines:
            line = line.strip()
            if len(line) > 0 and not line.startswith("#"):
                auth = {}
                for token in IMClient._split_line(line, maintain_quotes=True):
                    key_value = IMClient._split_line(token, "=")
                    if len(key_value) != 2:
                        break
                    else:
                        key = key_value[0].strip()
                        value = key_value[1].strip().replace("\\n", "\n")
                        auth[key] = IMClient._replace_auth_values(value)
                res.append(auth)

        return res

    # fetch the output using the command
    @staticmethod
    def _run_command(cmd):
        proc = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        outs, errs = proc.communicate()
        if proc.returncode != 0:
            if errs == b'':
                errs = outs
            raise Exception("Failed to get auth value using command %s: %s" % (cmd, errs.decode('utf-8')))
        return outs.decode('utf-8').replace('\n', '')

    @staticmethod
    def _get_input_params(radl):
        """
        Search for input parameters, ask the user for the values and replace them in the RADL
        """
        pos = 0
        while pos != -1:
            pos = radl.find("@input.", pos)
            if pos != -1:
                pos = pos + 7
                pos_fin = radl.find("@", pos)
                param_name = radl[pos:pos_fin]
                valor = input("Specify parameter " + param_name + ": ")
                radl = radl.replace("@input." + param_name + "@", valor)

        return radl

    @staticmethod
    def _get_master_vm_id(inf_id):
        return 0

    def _get_inf_id(self):
        if len(self.args) >= 1:
            inf_id = self.args[0]
            if inf_id.isdigit():
                inf_id = int(self.args[0])

            if self.options.name:
                success, infras = self._list_infras(flt=".*description\\s*.*\\s*(\\s*name\\s*=\\s*'%s'.*).*" % inf_id)
                if not success:
                    raise Exception("Error getting infrastructure list.")
                if len(infras) == 0:
                    raise Exception("Infrastructure Name not found")
                elif len(infras) >= 1:
                    if len(infras) > 1:
                        print("WARNING!: more that one infrastructure with the same name. First one returned.")
                    return infras[0]
            else:
                return inf_id
        else:
            raise Exception("Infrastructure ID not specified")

    def _get_vm_id(self):
        if len(self.args) >= 2:
            return self.args[1]
        else:
            raise Exception("VM ID not specified")

    def _get_radl(self, param_index, fail_if_not_set=True):
        if len(self.args) > param_index:
            if not os.path.isfile(self.args[param_index]):
                raise Exception("RADL file '%s' does not exist" % self.args[param_index])
            return self.args[param_index]
        elif fail_if_not_set:
            raise Exception("RADL file not specified")

    @staticmethod
    def read_input_file(filename):
        # Read the file
        _, file_extension = os.path.splitext(filename)
        f = open(filename)
        radl_data = "".join(f.readlines())
        f.close()
        desc_type = "radl"
        if file_extension in [".yaml", ".yml"]:
            radl = radl_data
            desc_type = "yaml"
        elif file_extension in [".json", ".jsn"]:
            radl = radl_data
            desc_type = "json"
        else:
            # check for input parameters @input.[param_name]@
            radl_data = IMClient._get_input_params(radl_data)
            radl = radl_parse.parse_radl(radl_data)
            radl.check()

        return radl, desc_type

    def create(self, inf_desc, desc_type="radl", asyncr=False):
        """
        Create an infrastructure
        Arguments:
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json" or "yaml")
           - asyncr(boolean): Flag to specify if the creation call will be asynchronous.
                              Default `False`.
        Returns: A tuple with the operation success (boolean) and the infrastructure ID in case of success
                 or the error message otherwise.
        """
        inf_id = None
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            if desc_type == "json":
                headers["Content-Type"] = "application/json"
            elif desc_type in "yaml":
                headers["Content-Type"] = "text/yaml"
            url = "%s/infrastructures" % self.options.restapi
            if asyncr:
                url += "?async=yes"
            resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                    data=str(inf_desc))
            success = resp.status_code == 200
            inf_id = resp.text
            if success:
                inf_id = os.path.basename(inf_id)
        else:
            (success, inf_id) = self.server.CreateInfrastructure(str(inf_desc), self.auth_data)

        return success, inf_id

    def _create(self):
        radl_file = self._get_radl(0)
        asyncr = False
        # by default asyncr is False, but in case of REST API, it is True
        if self.options.restapi:
            asyncr = True
        if len(self.args) >= 2:
            asyncr = bool(int(self.args[1]))

        # Read the file
        radl, desc_type = self.read_input_file(radl_file)

        return self.create(radl, desc_type, asyncr)

    def removeresource(self, inf_id, vm_list, context=None):
        """
        Remove resources from an infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_list(list of strings): List of VM IDs to delete.
           - context(boolean): Flag to disable the contextualization at the end.
        Returns: A tuple with the operation success (boolean) and the list of deleted VM IDs in case of success
                 or the error message otherwise.
        """
        vm_list = ",".join(str(vm_id) for vm_id in vm_list)
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi.rstrip("/"), inf_id, vm_list)
            if context is False:
                url += "?context=0"
            resp = requests.request("DELETE", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if success:
                vms_id = vm_list
            else:
                vms_id = resp.text
        else:
            (success, vms_id) = self.server.RemoveResource(inf_id, vm_list, self.auth_data, context)

        return True, vms_id

    def _removeresource(self):
        inf_id = self._get_inf_id()
        context = None
        if len(self.args) >= 2:
            vm_list = [int(vm_id) for vm_id in self.args[1].split(",")]

            if len(self.args) >= 3:
                if self.args[2] in ["0", "1"]:
                    context = bool(int(self.args[2]))
                else:
                    return False, "The ctxt flag must be 0 or 1"
        else:
            if self.options.restapi:
                msg = "VM ID to remove not specified"
            else:
                msg = "Coma separated VM list to remove not specified"
            return False, msg

        return self.removeresource(inf_id, vm_list, context)

    def addresource(self, inf_id, inf_desc, desc_type="radl", context=None):
        """
        Add resources into an infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json" or "yaml")
           - context(boolean): Flag to disable the contextualization at the end.
        Returns: A tuple with the operation success (boolean) and the list of added VM IDs in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            if desc_type == "yaml":
                headers["Content-Type"] = "text/yaml"
            elif desc_type == "json":
                headers["Content-Type"] = "application/json"
            url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
            if context is False:
                url += "?context=0"
            resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                    data=str(inf_desc))
            success = resp.status_code == 200
            restres = resp.text
            if success:
                vms_id = []
                for elem in resp.json()["uri-list"]:
                    vms_id.append(os.path.basename(list(elem.values())[0]))
            else:
                vms_id = restres
        else:
            (success, vms_id) = self.server.AddResource(inf_id, str(inf_desc), self.auth_data, context)

        return success, vms_id

    def _addresource(self):
        inf_id = self._get_inf_id()
        radl_file = self._get_radl(1)
        context = None
        if len(self.args) >= 3:
            if self.args[2] in ["0", "1"]:
                context = bool(int(self.args[2]))
            else:
                return False, "The ctxt flag must be 0 or 1"

        radl, desc_type = self.read_input_file(radl_file)

        return self.addresource(inf_id, radl, desc_type, context)

    def alter(self, inf_id, vm_id, inf_desc):
        """
        Modifies the features of a VM
        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - inf_desc(string): Infrastructure description in RADL (plain).
        Returns: A tuple with the operation success (boolean) and the RADL of the modified VM in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=str(inf_desc))
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.AlterVM(inf_id, vm_id, str(inf_desc), self.auth_data)

        return success, res

    def _alter(self):
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        radl_file = self._get_radl(2)

        radl = radl_parse.parse_radl(radl_file)

        return self.alter(inf_id, vm_id, radl)

    def reconfigure(self, inf_id, inf_desc, desc_type="radl", vm_list=None):
        """
        Reconfigure the infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - inf_desc(string): Infrastructure description in RADL (plain).
           - vm_list(list of strings): Optional list of VM IDs to reconfigure (default all).
        Returns: A tuple with the operation success (boolean) and an empty string in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            if desc_type == "json":
                headers["Content-Type"] = "application/json"
            elif desc_type in "yaml":
                headers["Content-Type"] = "text/yaml"
            url = "%s/infrastructures/%s/reconfigure" % (self.options.restapi, inf_id)
            if vm_list:
                url += "?vm_list=" + ",".join(str(vm_id) for vm_id in vm_list)
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=str(inf_desc))
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.Reconfigure(inf_id, str(inf_desc), self.auth_data, vm_list)

        return success, res

    def _reconfigure(self):
        inf_id = self._get_inf_id()
        radl = ""
        vm_list = None
        radl_file = self._get_radl(1, False)
        desc_type = "radl"
        if len(self.args) >= 3:
            vm_list = [int(vm_id) for vm_id in self.args[2].split(",")]

        if radl_file:
            # Read the file
            radl, desc_type = self.read_input_file(radl_file)

        return self.reconfigure(inf_id, radl, desc_type, vm_list)

    def get_infra_property(self, inf_id, prop):
        """
        Get an infrastructure property.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - prop(string): Property to get. Valid values: "radl", "contmsg", "state", "outputs"
        Returns: A tuple with the operation success (boolean) and the value of the prop in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            url = "%s/infrastructures/%s/%s" % (self.options.restapi, inf_id, prop)
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if success:
                res = resp.json()[prop]
            else:
                res = resp.text
        else:
            if prop == "state":
                (success, res) = self.server.GetInfrastructureState(inf_id, self.auth_data)
            elif prop == "contmsg":
                (success, res) = self.server.GetInfrastructureContMsg(inf_id, self.auth_data)
            elif prop == "radl":
                (success, res) = self.server.GetInfrastructureRADL(inf_id, self.auth_data)
            elif prop == "outputs":
                return False, "ERROR getting the infrastructure outputs: Only available with REST API."
            else:
                return False, "Invalid Operation."

        return success, res

    def _get_infra_property(self, prop):
        inf_id = self._get_inf_id()
        return self.get_infra_property(inf_id, prop)

    def _getvmcontmsg(self):
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        return self.getvminfo(inf_id, vm_id, "contmsg")

    def getvminfo(self, inf_id, vm_id, prop=None, system_name=None):
        """
        Get VM info.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - prop(string): Optional RADL property to get.
           - system_name(string): Optional system name to filter the VMs.
        Returns: A tuple with the operation success (boolean) and the value of the prop in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
            if prop and not system_name:
                url += "/" + prop
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if system_name and success:
                radl_info = radl_parse.parse_radl(resp.text)
                if radl_info.systems[0].name == system_name:
                    if prop:
                        info = radl_info.systems[0].getValue(prop)
                    else:
                        info = resp.text
                else:
                    info = ""
            else:
                info = resp.text
        else:
            if prop and not system_name:
                if prop == "contmsg":
                    (success, info) = self.server.GetVMContMsg(inf_id, vm_id, self.auth_data)
                else:
                    (success, info) = self.server.GetVMProperty(inf_id, vm_id, prop, self.auth_data)
            else:
                (success, info) = self.server.GetVMInfo(inf_id, vm_id, self.auth_data)
                if success and system_name:
                    radl_info = radl_parse.parse_radl(info)
                    if radl_info.systems[0].name == system_name:
                        if prop:
                            info = radl_info.systems[0].getValue(prop)
                    else:
                        info = ""

        return success, info

    def _getvminfo(self):
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()

        prop = None
        if len(self.args) >= 3:
            prop = self.args[2]

        return self.getvminfo(inf_id, vm_id, prop)

    def _get_vms_info_generator(self, inf_id, vm_ids, prop, system_name):
        """Helper function to return a generator."""
        for vm_id in vm_ids:
            success, radl = self.getvminfo(inf_id, vm_id, prop, system_name)
            yield vm_id, success, radl

    def getinfo(self, inf_id, prop=None, system_name=None):
        """
        Get infrastructure info.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - prop(string): Optional RADL property to get.
           - system_name(string): Optional system name to filter the VMs.
        Returns: A tuple with the operation success (boolean) and the value of the prop in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            restres = resp.text
            if success:
                vm_ids = []
                for elem in resp.json()["uri-list"]:
                    vm_ids.append(os.path.basename(list(elem.values())[0]))
            else:
                vm_ids = restres
        else:
            (success, vm_ids) = self.server.GetInfrastructureInfo(inf_id, self.auth_data)

        if success:
            return True, self._get_vms_info_generator(inf_id, vm_ids, prop, system_name)
        else:
            return False, "ERROR getting the information about the infrastructure: " + str(vm_ids)

    def _getinfo(self):
        inf_id = self._get_inf_id()
        prop = None
        if len(self.args) >= 2:
            prop = self.args[1]

        return self.getinfo(inf_id, prop, self.options.system_name)

    def destroy(self, inf_id, asyncr=False):
        """
        Destroy an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
           - asyncr(boolean): Flag to specify if the deletion call will be asynchronous.
                              Default `False`.
        Returns: A tuple with the operation success (boolean) and an empty string in case of success
                 or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
            if self.options.force:
                url += "?force=yes"
            if asyncr:
                url += "?async=yes"
            resp = requests.request("DELETE", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.DestroyInfrastructure(inf_id, self.auth_data, self.options.force)

        return success, res

    def _destroy(self):
        inf_id = self._get_inf_id()
        return self.destroy(inf_id)

    def list_infras(self, flt=None):
        """
        Get the list of user infrastructures

        Arguments:
           - flt(string): Optional filter (as regular expression) to filter the infrastructures.
        Returns: A tuple with the operation success (boolean) and the list of infrastructure IDs
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            url = "%s/infrastructures" % self.options.restapi
            if flt:
                url += "?filter=%s" % flt
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if success:
                res = []
                for elem in resp.json()["uri-list"]:
                    res.append(os.path.basename(list(elem.values())[0]))
            else:
                res = resp.text
        else:
            (success, res) = self.server.GetInfrastructureList(self.auth_data, flt)

        return success, res

    def _list_infras(self, show_name=False, flt=None):
        if flt is None and len(self.args) >= 1:
            flt = self.args[0]

        (success, res) = self.list_infras(flt)

        if success and show_name:
            inf_names = {}
            for inf_id in res:
                inf_names[inf_id] = "N/A"
                success, radl_data = self.get_infra_property(inf_id, "radl")
                if success:
                    radl = radl_parse.parse_radl(radl_data)
                    if radl.description and radl.description.getValue("name"):
                        inf_names[inf_id] = radl.description.getValue("name")
            res = inf_names

        return success, res

    def start_infra(self, inf_id):
        """
        Start an infrastructure (previously stopped)

        Arguments:
           - inf_id(string): Infrastructure ID.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        return self.infra_op(inf_id, "start")

    def stop_infra(self, inf_id):
        """
        Stop an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        return self.infra_op(inf_id, "stop")

    def infra_op(self, inf_id, operation):
        """
        Call an infrastructure operation (start or stop)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - operation(string): Operation to call: "start" or "stop".
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/%s" % (self.options.restapi, inf_id, operation)
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            res = resp.text
        else:
            if operation == "stop":
                (success, res) = self.server.StopInfrastructure(inf_id, self.auth_data)
            elif operation == "start":
                (success, res) = self.server.StartInfrastructure(inf_id, self.auth_data)
            else:
                return False, "Invalid Operation."
        return success, res

    def _infra_op(self, operation):
        inf_id = self._get_inf_id()
        return self.infra_op(inf_id, operation)

    def start_vm(self, inf_id, vm_id):
        """
        Start an VM (previously stopped)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        return self.vm_op(inf_id, vm_id, "start")

    def stop_vm(self, inf_id, vm_id):
        """
        Stop an VM

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        return self.vm_op(inf_id, vm_id, "stop")

    def reboot_vm(self, inf_id, vm_id):
        """
        Reboot an VM

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        return self.vm_op(inf_id, vm_id, "reboot")

    def vm_op(self, inf_id, vm_id, operation):
        """
        Call a VM operation (start, stop or reboot)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - operation(string): Operation to call: "start", "stop" or "reboot".
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s/%s" % (self.options.restapi, inf_id, vm_id, operation)
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            info = resp.text
        else:
            if operation == "start":
                (success, info) = self.server.StartVM(inf_id, vm_id, self.auth_data)
            elif operation == "stop":
                (success, info) = self.server.StopVM(inf_id, vm_id, self.auth_data)
            elif operation == "reboot":
                (success, info) = self.server.RebootVM(inf_id, vm_id, self.auth_data)
            else:
                return False, "Invalid Operation."

        return success, info

    def _vm_op(self, operation):
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        return self.vm_op(inf_id, vm_id, operation)

    def _ssh(self, operation):
        inf_id = self._get_inf_id()
        show_only = False
        master_vm_id = None
        cmd = None
        if operation in ["ssh", "put", "get"]:
            master_vm_id = self._get_master_vm_id(inf_id)
            vm_id = master_vm_id
            if len(self.args) >= 2:
                if self.args[1] in ["0", "1"]:
                    show_only = bool(int(self.args[1]))
                else:
                    return False, "The show_only flag must be 0 or 1"
                if len(self.args) >= 3:
                    cmd = self.args[2:]
        else:
            if len(self.args) >= 2:
                vm_id = self.args[1]
                if len(self.args) >= 3:
                    if self.args[2] in ["0", "1"]:
                        show_only = bool(int(self.args[2]))
                    else:
                        return False, "The show_only flag must be 0 or 1"
                    if len(self.args) >= 4:
                        cmd = self.args[3:]
            else:
                return False, "VM ID to get info not specified"

        self.args = [inf_id, vm_id]
        vm_success, vm_info = self._getvminfo()

        if vm_success:
            radl = radl_parse.parse_radl(vm_info)
        else:
            return vm_success, "Error accessing VM: %s" % vm_info

        proxy_host = False
        for netid in radl.systems[0].getNetworkIDs():
            net = radl.get_network_by_id(netid)
            if net.getValue("proxy_host"):
                proxy_host = True

        if not radl.getPublicIP() and master_vm_id is None and not proxy_host:
            vm_id = IMClient._get_master_vm_id(inf_id)
            if not self.options.quiet:
                print("VM ID %s does not has public IP, try to access via VM ID 0." % vm_id)

            self.args = [inf_id, vm_id]
            vm_success, vm_info = self._getvminfo()

            if vm_success:
                radl2 = radl_parse.parse_radl(vm_info)
                host = radl2.getPublicIP()
                username = radl2.systems[0].getValue("disk.0.os.credentials.username")
                password = radl2.systems[0].getValue("disk.0.os.credentials.password")
                priv_key = radl2.systems[0].getValue("disk.0.os.credentials.private_key")

                for netid in radl.systems[0].getNetworkIDs():
                    net = radl.get_network_by_id(netid)
                    if password:
                        proxy_host = "%s:%s@%s" % (username, password, host)
                    elif priv_key:
                        proxy_host = "%s@%s" % (username, host)
                        net.setValue('proxy_key', priv_key)
                        proxy_key_filename = "/var/tmp/%s_%s_%s.pem" % (username, username, radl.getPrivateIP())
                        with open(proxy_key_filename, "w") as f:
                            f.write(priv_key)
                        os.chmod(proxy_key_filename, 0o600)
                    else:
                        return False, "Error, no valid credentials in VM 0"
                    net.setValue('proxy_host', proxy_host)
            else:
                return False, "Error accessing VM: %s" % vm_info

        return True, (radl, show_only, cmd)

    def getversion(self):
        """
        Get IM server version

        Returns: A tuple with the operation success (boolean) and the version string
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            url = "%s/version" % self.options.restapi
            resp = requests.request("GET", url, verify=self.options.verify)
            success = resp.status_code == 200
            version = resp.text
        else:
            (success, version) = self.server.GetVersion()

        return success, version

    def export_data(self, inf_id, delete=None):
        """
        Export infrastructure data

        Arguments:
           - inf_id(string): Infrastructure ID.
           - delete(boolean): Flag to specify if the infrastructure will be deleted after exporting the data.
                              Default `False`.
        Returns: A tuple with the operation success (boolean) and the json data of the infrastructure
                 in case of success or the error message otherwise.
        """
        if len(self.args) >= 2:
            delete = bool(int(self.args[1]))

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            url = "%s/infrastructures/%s/data" % (self.options.restapi, inf_id)
            if delete:
                url += "?delete=yes"
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if success:
                data = resp.json()["data"]
            else:
                data = resp.text
        else:
            (success, data) = self.server.ExportInfrastructure(inf_id, delete, self.auth_data)

        return success, data

    def _export_data(self):
        inf_id = self._get_inf_id()
        delete = None
        if len(self.args) >= 2:
            delete = bool(int(self.args[1]))
        return self.export_data(inf_id, delete)

    def import_data(self, data):
        """
        Import infrastructure data

        Arguments:
           - data(string): Json data with the Infrastructure info.
        Returns: A tuple with the operation success (boolean) and the ID of the imported infrastructure
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures" % self.options.restapi
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=data)
            success = resp.status_code == 200
            inf_id = resp.text
            if success:
                inf_id = os.path.basename(inf_id)
        else:
            (success, inf_id) = self.server.ImportInfrastructure(data, self.auth_data)

        return success, inf_id

    def _import_data(self):
        if len(self.args) >= 1:
            if not os.path.isfile(self.args[0]):
                return False, "JSON file '" + self.args[0] + "' does not exist"
        else:
            return False, "JSON file to create inf. not specified"

        f = open(self.args[0])
        data = "".join(f.readlines())
        f.close()

        return self.import_data(data)

    def get_cloud_images(self, cloud_id):
        """
        Get Cloud provider images

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
        Returns: A tuple with the operation success (boolean) and the requested data
                 in case of success or the error message otherwise.
        """
        return self.get_cloud_info(cloud_id, "images")

    def get_cloud_quotas(self, cloud_id):
        """
        Get Cloud provider quotas

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
        Returns: A tuple with the operation success (boolean) and the requested data
                 in case of success or the error message otherwise.
        """
        return self.get_cloud_info(cloud_id, "quotas")

    def get_cloud_info(self, cloud_id, operation):
        """
        Get Cloud provider info

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
           - operation(string): Type of information to get: "images" or "quotas".
        Returns: A tuple with the operation success (boolean) and the requested data
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            url = "%s/clouds/%s/%s" % (self.options.restapi, cloud_id, operation)
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            if success:
                data = resp.json()[operation]
            else:
                data = resp.text
        else:
            if operation == "images":
                (success, data) = self.server.GetCloudImageList(cloud_id, self.auth_data)
            elif operation == "quotas":
                (success, data) = self.server.GetCloudQuotas(cloud_id, self.auth_data)
            else:
                return False, "Invalid Operation."

        return success, data

    def _get_cloud_info(self, operation):
        if not len(self.args) >= 1:
            return False, "Cloud ID not specified"

        cloud_id = self.args[0]
        return self.get_cloud_info(cloud_id, operation)

    def _wait(self):
        self._get_inf_id()
        max_time = 36000  # 10h
        if len(self.args) >= 2:
            max_time = int(self.args[1])
        unknown_count = 0
        wait = 0
        state = "pending"
        while state in ["pending", "running", "unknown"] and unknown_count < 3 and wait < max_time:

            success, res = self._get_infra_property("state")

            if success:
                state = res['state']
            else:
                state = "unknown"

            if state == "unknown":
                unknown_count += 1

            if state in ["pending", "running", "unknown"]:
                if not self.options.quiet:
                    print("The infrastructure is in state: %s. Wait ..." % state)
                time.sleep(30)
                wait += 30

        if state == "configured":
            return True, "The infrastructure is in state: %s" % state
        elif wait >= max_time:
            return False, "Timeout waiting."
        else:
            return False, "The infrastructure is in state: %s" % state

    def change_auth(self, inf_id, new_auth_data, overwrite=None):
        """
        Change ownership of an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
           - new_auth_data(string): New Infrastructure Manager auth data to set.
           - overwrite(boolean): Flag to specify if the auth data will be overwrited.
                                 Default `False`.
        Returns: A tuple with the operation success (boolean) and an empty string
                 in case of success or the error message otherwise.
        """
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/authorization" % (self.options.restapi, inf_id)
            if overwrite:
                url += "?overwrite=1"
            resp = requests.request("POST", url, verify=self.options.verify,
                                    headers=headers, data=json.dumps(new_auth_data[0]))
            success = resp.status_code == 200
            info = resp.text
        else:
            (success, info) = self.server.ChangeInfrastructureAuth(inf_id, new_auth_data[0], overwrite, self.auth_data)

        return success, info

    def _change_auth(self):
        inf_id = self._get_inf_id()
        if len(self.args) >= 2:
            if not os.path.isfile(self.args[1]):
                return False, "New auth file '" + self.args[1] + "' does not exist"
        else:
            return False, "JSON file to create inf. not specified"

        new_auth_data = []
        for elem in IMClient.read_auth_data(self.args[1]):
            if "type" in elem and elem["type"] == "InfrastructureManager":
                new_auth_data.append(elem)
                break

        if not new_auth_data:
            return False, "No new InfrastructureManager auth provided."

        overwrite = False
        if len(self.args) >= 3:
            if self.args[2] in ["0", "1"]:
                overwrite = bool(int(self.args[2]))
            else:
                return False, "The overwrite flag must be 0 or 1"

        return self.change_auth(inf_id, new_auth_data, overwrite)
