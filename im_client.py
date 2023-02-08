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
    from xmlrpclib import ServerProxy
except ImportError:
    from xmlrpc.client import ServerProxy

try:
    # To avoid annoying InsecureRequestWarning messages in some Connectors
    import requests.packages
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass

import json
import sys
import os
import subprocess
import tempfile
import time
from optparse import OptionParser, Option, IndentedHelpFormatter
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

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
    def run(radl, show_only=False):
        try:
            if radl.systems[0].getValue("disk.0.os.credentials.private_key"):
                ops = CmdSsh._connect_key(radl)
            else:
                ops = CmdSsh._connect_password(radl)

            if show_only:
                print(" ".join(ops))
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
               "ssh", "-p", ssh_port, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no",
               "%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip)]

        if ssh_args:
            res.extend(ssh_args)

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
               "-o", "StrictHostKeyChecking=no",
               "%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip)]

        if ssh_args:
            res.extend(ssh_args)

        return res


class IMClient:

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
    def replace_auth_values(value):
        # Enable to specify a commnad and set the contents of the output
        if value.startswith("command(") and value.endswith(")"):
            command = value[8:-1]
            return IMClient._run_command(command)
        # Enable to specify a filename and set the contents of it
        elif value.startswith("file(") and value.endswith(")"):
            try:
                with open(value[5:-1], 'r') as f:
                    data = f.read()
                return data.strip()
            except Exception:
                pass
        return value

    @staticmethod
    def split_line(line, separator=";", maintain_quotes=False):
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
        if isinstance(filename, list):
            lines = filename
        else:
            auth_file = open(filename, 'r')
            lines = auth_file.readlines()
            auth_file.close()

        res = []

        if len(lines) == 1 and lines[0].startswith("Bearer "):
            token = lines[0].strip()[7:]
            return "Bearer %s" % IMClient.replace_auth_values(token)

        for line in lines:
            line = line.strip()
            if len(line) > 0 and not line.startswith("#"):
                auth = {}
                for token in IMClient.split_line(line, maintain_quotes=True):
                    key_value = IMClient.split_line(token, "=")
                    if len(key_value) != 2:
                        break
                    else:
                        key = key_value[0].strip()
                        value = key_value[1].strip().replace("\\n", "\n")
                        auth[key] = IMClient.replace_auth_values(value)
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
    def get_input_params(radl):
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
    def get_master_vm_id(inf_id):
        return 0

    def get_inf_id(self):
        if len(self.args) >= 1:
            inf_id = self.args[0]
            if inf_id.isdigit():
                inf_id = int(self.args[0])

            if self.options.name:
                success, infras = self.list_infras(flt=".*description\s*.*\s*(\s*name\s*=\s*'%s'.*).*" % inf_id)
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

    def get_vm_id(self):
        if len(self.args) >= 2:
            return self.args[1]
        else:
            raise Exception("VM ID not specified")

    def get_radl(self, param_index, fail_if_not_set=True):
        if len(self.args) > param_index:
            if not os.path.isfile(self.args[param_index]):
                raise Exception("RADL file '%s' does not exist" % self.args[param_index])
            return self.args[param_index]
        elif fail_if_not_set:
            raise Exception("RADL file not specified")

    def create(self):
        radl_file = self.get_radl(0)
        asyncr = False
        if len(self.args) >= 2:
            asyncr = bool(int(self.args[1]))

        # Read the file
        _, file_extension = os.path.splitext(radl_file)
        f = open(radl_file)
        radl_data = "".join(f.readlines())
        f.close()
        if file_extension in [".yaml", ".yml", ".json", ".jsn"]:
            radl = radl_data
        else:
            # check for input parameters @input.[param_name]@
            radl_data = IMClient.get_input_params(radl_data)
            radl = radl_parse.parse_radl(radl_data)
            radl.check()

        inf_id = None
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            if file_extension in [".json", ".jsn"]:
                headers["Content-Type"] = "application/json"
            elif file_extension in [".yaml", ".yml"]:
                headers["Content-Type"] = "text/yaml"
            url = "%s/infrastructures" % self.options.restapi
            if asyncr:
                url += "?async=yes"
            resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                    data=str(radl))
            success = resp.status_code == 200
            inf_id = resp.text
            if success:
                inf_id = os.path.basename(inf_id)
        else:
            (success, inf_id) = self.server.CreateInfrastructure(str(radl), self.auth_data)

        return success, inf_id

    def removeresource(self):
        inf_id = self.get_inf_id()
        context = True
        if len(self.args) >= 2:
            vm_list = self.args[1]

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

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi.rstrip("/"), inf_id, vm_list)
            if not context:
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

    def addresource(self):
        inf_id = self.get_inf_id()
        radl_file = self.get_radl(1)
        context = True
        if len(self.args) >= 3:
            if self.args[2] in ["0", "1"]:
                context = bool(int(self.args[2]))
            else:
                return False, "The ctxt flag must be 0 or 1"

        _, file_extension = os.path.splitext(radl_file)
        if file_extension in [".yaml", ".yml"]:
            f = open(radl_file)
            radl = "".join(f.readlines())
            f.close()
        else:
            radl = radl_parse.parse_radl(radl_file)
            radl.check()

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
            if file_extension in [".yaml", ".yml"]:
                headers["Content-Type"] = "text/yaml"
            url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
            if not context:
                url += "?context=0"
            resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                    data=str(radl))
            success = resp.status_code == 200
            restres = resp.text
            if success:
                vms_id = []
                for elem in resp.json()["uri-list"]:
                    vms_id.append(os.path.basename(list(elem.values())[0]))
            else:
                vms_id = restres
        else:
            (success, vms_id) = self.server.AddResource(inf_id, str(radl), self.auth_data, context)

        return success, vms_id

    def alter(self):
        inf_id = self.get_inf_id()
        vm_id = self.get_vm_id()
        radl_file = self.get_radl(2)

        radl = radl_parse.parse_radl(radl_file)

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=str(radl))
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.AlterVM(inf_id, vm_id, str(radl), self.auth_data)

        return success, res

    def reconfigure(self):
        inf_id = self.get_inf_id()
        radl = ""
        vm_list = None
        radl_file = self.get_radl(1, False)
        if len(self.args) >= 3:
            vm_list = [int(vm_id) for vm_id in self.args[2].split(",")]

        if radl_file:
            # Read the file
            f = open(radl_file)
            radl_data = "".join(f.readlines())
            f.close()
            radl = radl_parse.parse_radl(radl_data)

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/reconfigure" % (self.options.restapi, inf_id)
            if len(self.args) >= 3:
                url += "?vm_list=" + self.args[2]
            resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=str(radl))
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.Reconfigure(inf_id, str(radl), self.auth_data, vm_list)

        return success, res

    def get_infra_property(self, prop, inf_id=None):
        if not inf_id:
            inf_id = self.get_inf_id()

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

    def getvminfo(self):
        inf_id = self.get_inf_id()
        vm_id = self.get_vm_id()

        propiedad = None
        if len(self.args) >= 3:
            propiedad = self.args[2]

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
            if propiedad:
                url += "/" + propiedad
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            info = resp.text
        else:
            if propiedad:
                (success, info) = self.server.GetVMProperty(inf_id, vm_id, propiedad, self.auth_data)
            else:
                (success, info) = self.server.GetVMInfo(inf_id, vm_id, self.auth_data)

        return success, info

    def _get_vms_info_generator(self, inf_id, vm_ids, propiedad):
        """Helper function to return a generator."""
        for vm_id in vm_ids:
            self.args = [inf_id, vm_id, propiedad]
            success, radl = self.getvminfo()
            yield vm_id, success, radl

    def getinfo(self):
        inf_id = self.get_inf_id()
        propiedad = None
        if len(self.args) >= 2:
            propiedad = self.args[1]

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
            return True, self._get_vms_info_generator(inf_id, vm_ids, propiedad)
        else:
            return False, "ERROR getting the information about the infrastructure: " + str(vm_ids)

    def destroy(self):
        inf_id = self.get_inf_id()
        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
            if self.options.force:
                url += "?force=yes"
            resp = requests.request("DELETE", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            res = resp.text
        else:
            (success, res) = self.server.DestroyInfrastructure(inf_id, self.auth_data, self.options.force)

        return success, res

    def list_infras(self, show_name=False, flt=None):
        if flt is None and len(self.args) >= 1:
            flt = self.args[0]

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

        if success and show_name:
            inf_names = {}
            for inf_id in res:
                inf_names[inf_id] = "N/A"
                success, radl_data = self.get_infra_property("radl", inf_id)
                if success:
                    radl = radl_parse.parse_radl(radl_data)
                    if radl.description and radl.description.getValue("name"):
                        inf_names[inf_id] = radl.description.getValue("name")
            res = inf_names

        return success, res

    def infra_op(self, operation):
        inf_id = self.get_inf_id()
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

    def getvmcontmsg(self):
        inf_id = self.get_inf_id()
        vm_id = self.get_vm_id()

        if self.options.restapi:
            headers = {"Authorization": self.rest_auth_data}
            url = "%s/infrastructures/%s/vms/%s/contmsg" % (self.options.restapi, inf_id, vm_id)
            resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
            success = resp.status_code == 200
            info = resp.text
        else:
            (success, info) = self.server.GetVMContMsg(inf_id, vm_id, self.auth_data)

        return success, info

    def vm_op(self, operation):
        inf_id = self.get_inf_id()
        vm_id = self.get_vm_id()

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

    def ssh(self, operation):
        inf_id = self.get_inf_id()
        show_only = False
        master_vm_id = None
        if operation == "ssh":
            master_vm_id = self.get_master_vm_id(inf_id)
            vm_id = master_vm_id
            if len(self.args) >= 2:
                if self.args[1] in ["0", "1"]:
                    show_only = bool(int(self.args[1]))
                else:
                    return False, "The show_only flag must be 0 or 1"
        else:
            if len(self.args) >= 2:
                vm_id = self.args[1]
                if len(self.args) >= 3:
                    if self.args[2] in ["0", "1"]:
                        show_only = bool(int(self.args[2]))
                    else:
                        return False, "The show_only flag must be 0 or 1"
            else:
                return False, "VM ID to get info not specified"

        self.args = [inf_id, vm_id]
        vm_success, vm_info = self.getvminfo()

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
            vm_id = IMClient.get_master_vm_id(inf_id)
            if not self.options.quiet:
                print("VM ID %s does not has public IP, try to access via VM ID 0." % vm_id)

            self.args = [inf_id, vm_id]
            vm_success, vm_info = self.getvminfo()

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

        return True, (radl, show_only)

    def getversion(self):
        if self.options.restapi:
            url = "%s/version" % self.options.restapi
            resp = requests.request("GET", url, verify=self.options.verify)
            success = resp.status_code == 200
            version = resp.text
        else:
            (success, version) = self.server.GetVersion()

        return success, version

    def export_data(self):
        inf_id = self.get_inf_id()
        delete = False
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

    def import_data(self):
        if len(self.args) >= 1:
            if not os.path.isfile(self.args[0]):
                return False, "JSON file '" + self.args[0] + "' does not exist"
        else:
            return False, "JSON file to create inf. not specified"

        f = open(self.args[0])
        data = "".join(f.readlines())
        f.close()

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

    def get_cloud_info(self, operation):
        if not len(self.args) >= 1:
            return False, "Cloud ID not specified"

        cloud_id = self.args[0]
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

    def wait(self):
        self.get_inf_id()
        max_time = 36000  # 10h
        if len(self.args) >= 2:
            max_time = int(self.args[1])
        unknown_count = 0
        wait = 0
        state = "pending"
        while state in ["pending", "running", "unknown"] and unknown_count < 3 and wait < max_time:

            success, res = self.get_infra_property("state")

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

    def change_auth(self):
        inf_id = self.get_inf_id()
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


def main(operation, options, args, parser):
    """
    Launch Client
    """
    if options.xmlrpc:
        options.restapi = None
    elif options.restapi is None:
        options.restapi = "http://localhost:8800"

    if (operation not in ["removeresource", "addresource", "create", "destroy", "getinfo", "list", "stop", "start",
                          "alter", "getcontmsg", "getvminfo", "reconfigure", "getradl", "getvmcontmsg", "stopvm",
                          "startvm", "sshvm", "ssh", "getstate", "getversion", "export", "import", "getoutputs",
                          "rebootvm", "cloudusage", "cloudimages", "wait", "create_wait_outputs", "change_auth"]):
        parser.error("operation not recognised.  Use --help to show all the available operations")

    auth_data = None
    if (operation not in ["getversion"]):
        if options.auth_file is None:
            parser.error("Auth file not specified")

        auth_data = IMClient.read_auth_data(options.auth_file)

        if auth_data is None:
            parser.error("Auth file with incorrect format.")

    imclient = IMClient(options, auth_data, args)

    if not options.quiet:
        url = options.restapi if options.restapi else options.xmlrpc
        if url.startswith("https"):
            print("Secure connection with: " + url)
        else:
            print("Connected with: " + url)

    if operation == "removeresource":
        success, vms_id = imclient.removeresource()
        if success:
            if not options.quiet:
                print("Resources with IDs: %s successfully deleted." % str(vms_id))
        else:
            print("ERROR deleting resources from the infrastructure: %s" % vms_id)
        return success

    elif operation == "addresource":
        success, vms_id = imclient.addresource()
        if success:
            if not options.quiet:
                print("Resources with IDs: %s successfully added." % ",".join(vms_id))
            else:
                print(json.dumps(vms_id, indent=4))
        else:
            print("ERROR adding resources to infrastructure: %s" % vms_id)
        return success

    elif operation == "create":
        success, inf_id = imclient.create()
        if success:
            if not options.quiet:
                print("Infrastructure successfully created with ID: %s" % str(inf_id))
        else:
            if not options.quiet:
                print("ERROR creating the infrastructure: %s" % inf_id)
        return success

    elif operation == "alter":
        success, res = imclient.alter()
        if success:
            if not options.quiet:
                print("VM successfully modified.")
        else:
            print("ERROR modifying the VM: %s" % res)
        return success

    elif operation == "reconfigure":
        success, res = imclient.reconfigure()
        if success:
            if not options.quiet:
                print("Infrastructure successfully reconfigured.")
        else:
            print("ERROR reconfiguring the infrastructure: " + res)
        return success

    elif operation == "getcontmsg":
        success, cont_out = imclient.get_infra_property("contmsg")
        if success:
            if len(cont_out) > 0:
                if not options.quiet:
                    print("Msg Contextualizator: \n")
                print(cont_out)
            elif not options.quiet:
                print("No Msg Contextualizator avaliable\n")
        else:
            print("Error getting infrastructure contextualization message: %s" % cont_out)
        return success

    elif operation == "getstate":
        success, res = imclient.get_infra_property("state")
        if success:
            if not options.quiet:
                state = res['state']
                vm_states = res['vm_states']
                print("The infrastructure is in state: %s" % state)
                for vm_id, vm_state in vm_states.items():
                    print("VM ID: %s is in state: %s." % (vm_id, vm_state))
            else:
                print(json.dumps(res, indent=4))
        else:
            print("Error getting infrastructure state: %s" % res)
        return success

    elif operation == "getvminfo":
        success, info = imclient.getvminfo()
        if not success:
            print("ERROR getting the VM info: %s" % info)
        print(info)
        return success

    elif operation == "getinfo":
        success, vms_info = imclient.getinfo()
        if success:
            for vm_id, vm_succes, vm_radl in vms_info:
                if not options.quiet:
                    print("Info about VM with ID: %s" % vm_id)
                if vm_succes:
                    print(vm_radl)
                else:
                    print("ERROR getting the information about the VM: " + vm_radl)
        else:
            print("ERROR getting the information about infrastructure: " + vms_info)
        return success

    elif operation == "destroy":
        success, res = imclient.destroy()
        if success:
            if not options.quiet:
                print("Infrastructure successfully destroyed")
        else:
            print("ERROR destroying the infrastructure: %s" % res)
        return success

    elif operation == "list":
        success, res = imclient.list_infras(show_name=options.name)
        if success:
            if res:
                if options.quiet:
                    print(json.dumps(res, indent=4))
                else:
                    if options.name:
                        print("Infrastructure ID                       Name")
                        print("====================================    ====")
                        print("\n".join(["%s    %s" % (inf_id, name) for inf_id, name in res.items()]))
                    else:
                        print("Infrastructure IDs: \n  %s" % ("\n  ".join([str(inf_id) for inf_id in res])))
            else:
                if not options.quiet:
                    print("No Infrastructures.")
        else:
            print("ERROR listing then infrastructures: %s" % res)
        return success

    elif operation == "start":
        success, res = imclient.infra_op(operation)
        if success:
            if not options.quiet:
                print("Infrastructure successfully started")
        else:
            print("ERROR starting the infraestructure: " + res)
        return success

    elif operation == "stop":
        success, res = imclient.infra_op(operation)
        if success:
            if not options.quiet:
                print("Infrastructure successfully stopped")
        else:
            print("ERROR stopping the infrastructure: " + res)
        return success

    elif operation == "getradl":
        success, radl = imclient.get_infra_property("radl")
        if success:
            print(radl)
        else:
            print("ERROR getting the infrastructure RADL: %s" % radl)
        return success

    elif operation == "getvmcontmsg":
        success, info = imclient.getvmcontmsg()
        if success:
            print(info)
        else:
            print("Error getting VM contextualization message: %s" % info)
        return success

    elif operation == "startvm":
        success, info = imclient.vm_op("start")
        if success:
            if not options.quiet:
                print("VM successfully started")
        else:
            print("Error starting VM: %s" % info)

        return success

    elif operation == "stopvm":
        success, info = imclient.vm_op("stop")
        if success:
            if not options.quiet:
                print("VM successfully stopped")
        else:
            print("Error stopping VM: %s" % info)
        return success

    elif operation == "rebootvm":
        success, info = imclient.vm_op("reboot")
        if success:
            if not options.quiet:
                print("VM successfully rebooted")
        else:
            print("Error rebooting VM: %s" % info)
        return success

    elif operation in ["sshvm", "ssh"]:
        success, res = imclient.ssh(operation)
        if success:
            try:
                radl, show_only = res
                CmdSsh.run(radl, show_only)
            except Exception as ex:
                print(str(ex))
                return False
            return True
        else:
            print(res)
            return False

    elif operation == "getversion":
        success, version = imclient.getversion()
        if success:
            if not options.quiet:
                print("IM service version: %s" % version)
            else:
                print(version)
        else:
            print("ERROR getting IM service version: " + version)
        return success

    elif operation == "export":
        success, data = imclient.export_data()
        if success:
            print(data)
        else:
            print("ERROR exporting data: " + data)
        return success

    elif operation == "import":
        success, inf_id = imclient.import_data()
        if success:
            if not options.quiet:
                print("New Inf: " + inf_id)
            else:
                print(inf_id)
        else:
            print("ERROR importing data: " + inf_id)
        return success

    elif operation == "getoutputs":
        success, outputs = imclient.get_infra_property("outputs")
        if success:
            if not options.quiet:
                print("The infrastructure outputs:\n")
                for key, value in outputs.items():
                    print("%s = %s" % (key, value))
            else:
                print(json.dumps(outputs, indent=4))
        return success

    elif operation == "cloudimages":
        success, data = imclient.get_cloud_info("images")
        if success:
            print(json.dumps(data, indent=4))
        else:
            print("ERROR getting cloud image list: " + data)
        return success

    elif operation == "cloudusage":
        success, data = imclient.get_cloud_info("quotas")
        if success:
            print(json.dumps(data, indent=4))
        else:
            print("ERROR getting cloud usage: " + data)
        return success

    elif operation == "wait":
        success, info = imclient.wait()
        if success:
            if not options.quiet:
                print(info)
        else:
            print(info)
        return success

    elif operation == "create_wait_outputs":
        success, inf_id = imclient.create()
        if not success:
            print('{"error": "%s"}' % inf_id)
            return False
        imclient.args = [inf_id]
        success, error = imclient.wait()
        if not success:
            print('{"infid": "%s", "error": "%s"}' % (inf_id, error))
            return False
        success, outputs = imclient.get_infra_property("outputs")
        if success:
            outputs["infid"] = inf_id
            print(json.dumps(outputs))
        else:
            print('{"infid": "%s", "outputs": {}}' % inf_id)
        return True

    elif operation == "change_auth":
        success, error = imclient.change_auth()
        if success:
            if not options.quiet:
                print("Auth data successfully changed.")
        else:
            print("ERROR changing auth data: " + error)
        return success


def get_parser():
    """
    Get Client parser
    """

    config = ConfigParser.RawConfigParser()
    config.read(['im_client.cfg', os.path.expanduser('~/.im_client.cfg')])

    default_auth_file = None
    default_xmlrpc = None
    default_restapi = None

    if config.has_option('im_client', "auth_file"):
        default_auth_file = config.get('im_client', "auth_file")
    if config.has_option('im_client', "xmlrpc_url"):
        default_xmlrpc = config.get('im_client', "xmlrpc_url")
    if config.has_option('im_client', "restapi_url"):
        default_restapi = config.get('im_client', "restapi_url")

    NOTICE = "\n\n\
IM - Infrastructure Manager\n\
Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia\n\
This program comes with ABSOLUTELY NO WARRANTY; for details please\n\
read the terms at http://www.gnu.org/licenses/gpl-3.0.txt.\n\
This is free software, and you are welcome to redistribute it\n\
under certain conditions; please read the license at \n\
http://www.gnu.org/licenses/gpl-3.0.txt for details."

    parser = PosOptionParser(usage="%prog [-u|--xmlrpc-url <url>] [-r|--restapi-url <url>] [-v|--verify-ssl] "
                             "[-a|--auth_file <filename>] operation op_parameters" + NOTICE, version="%prog 1.5.11")
    parser.add_option("-a", "--auth_file", dest="auth_file", nargs=1, default=default_auth_file, help="Authentication"
                      " data file", type="string")
    parser.add_option("-u", "--xmlrpc-url", dest="xmlrpc", nargs=1, default=default_xmlrpc, help="URL address of the "
                      "InfrastructureManager XML-RCP daemon", type="string")
    parser.add_option("-r", "--rest-url", dest="restapi", nargs=1, default=default_restapi, help="URL address of the "
                      "InfrastructureManager REST API", type="string")
    parser.add_option("-v", "--verify-ssl", action="store_true", default=False, dest="verify",
                      help="Verify the certificate of the InfrastructureManager XML-RCP server")
    parser.add_option("-f", "--force", action="store_true", default=False, dest="force",
                      help="Force the deletion of the infrastructure")
    parser.add_option("-q", "--quiet", action="store_true", default=False, dest="quiet",
                      help="Work in quiet mode")
    parser.add_option("-n", "--name", action="store_true", default=False, dest="name",
                      help="Show/User Infra name-")
    parser.add_operation_help('list', '')
    parser.add_operation_help('create', '<radl_file> [async_flag]')
    parser.add_operation_help('destroy', '<inf_id>')
    parser.add_operation_help('getinfo', '<inf_id> [radl_attribute]')
    parser.add_operation_help('getradl', '<inf_id>')
    parser.add_operation_help('getcontmsg', '<inf_id>')
    parser.add_operation_help('getstate', '<inf_id>')
    parser.add_operation_help('getvminfo', '<inf_id> <vm_id> [radl_attribute]')
    parser.add_operation_help('getvmcontmsg', '<inf_id> <vm_id>')
    parser.add_operation_help('addresource', '<inf_id> <radl_file> [ctxt flag]')
    parser.add_operation_help('removeresource', '<inf_id> <vm_id> [ctxt flag]')
    parser.add_operation_help('alter', '<inf_id> <vm_id> <radl_file>')
    parser.add_operation_help('start', '<inf_id>')
    parser.add_operation_help('stop', '<inf_id>')
    parser.add_operation_help('reconfigure', '<inf_id> [<radl_file>] [vm_list]')
    parser.add_operation_help('startvm', '<inf_id> <vm_id>')
    parser.add_operation_help('stopvm', '<inf_id> <vm_id>')
    parser.add_operation_help('rebootvm', '<inf_id> <vm_id>')
    parser.add_operation_help('sshvm', '<inf_id> <vm_id> [show_only]')
    parser.add_operation_help('ssh', '<inf_id> [show_only]')
    parser.add_operation_help('export', '<inf_id> [delete]')
    parser.add_operation_help('import', '<json_file>')
    parser.add_operation_help('getoutputs', '<inf_id>')
    parser.add_operation_help('cloudusage', '<cloud_id>')
    parser.add_operation_help('cloudimages', '<cloud_id>')
    parser.add_operation_help('getversion', '')
    parser.add_operation_help('wait', '<inf_id> <max_time>')
    parser.add_operation_help('create_wait_outputs', '<radl_file>')
    parser.add_operation_help('change_auth', '<inf_id> <new_auth_file>')

    return parser


if __name__ == "__main__":

    parser = get_parser()
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error("operation not specified. Use --help to show all the available operations.")
    operation = args[0].lower()
    args = args[1:]

    try:
        if main(operation, options, args, parser):
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as ex:
        print(str(ex))
        sys.exit(1)
