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
except:
    from xmlrpc.client import ServerProxy

import sys
import os
import tempfile
from optparse import OptionParser, Option, IndentedHelpFormatter
try:
    import ConfigParser
except:
    import configparser as ConfigParser

from radl import radl_parse

__version__ = "1.5.2"


class PosOptionParser(OptionParser):
    def format_help(self, formatter=None):
        class Positional(object):
            def __init__(self, args):
                self.option_groups = []
                self.option_list = args

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
        try:
            args = self.positional
        except AttributeError:
            args = []
        args.append(Option('--' + arg, action='store_true', help=helpstr))
        self.positional = args

    def set_out(self, out):
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
            outports = public_net.getOutPorts()
            if outports:
                for outport in outports:
                    if outport.get_local_port() == 22 and outport.get_protocol() == "tcp":
                        ssh_port = outport.get_remote_port()

        return str(ssh_port)

    @staticmethod
    def _connect_password(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        return ["sshpass", "-p%s" % s.getValue("disk.0.os.credentials.password"),
                "ssh", "-p", ssh_port, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no",
                "%s@%s" % (s.getValue("disk.0.os.credentials.username"), radl.getPublicIP())]

    @staticmethod
    def _connect_key(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(s.getValue("disk.0.os.credentials.private_key"))
        f.close()
        return ["ssh", "-p", ssh_port, "-i", f.name, "-o", "UserKnownHostsFile=/dev/null",
                "-o", "StrictHostKeyChecking=no",
                "%s@%s" % (s.getValue("disk.0.os.credentials.username"), radl.getPublicIP())]


# From IM.auth
def read_auth_data(filename):
    if isinstance(filename, list):
        lines = filename
    else:
        auth_file = open(filename, 'r')
        lines = auth_file.readlines()
        auth_file.close()

    res = []

    for line in lines:
        line = line.strip()
        if len(line) > 0 and not line.startswith("#"):
            auth = {}
            tokens = line.split(";")
            for token in tokens:
                key_value = token.split(" = ")
                if len(key_value) != 2:
                    break
                else:
                    value = key_value[1].strip().replace("\\n", "\n")
                    # Enable to specify a filename and set the contents of it
                    if value.startswith("file(") and value.endswith(")"):
                        filename = value[5:len(value) - 1]
                        try:
                            value_file = open(filename, 'r')
                            value = value_file.read()
                            value_file.close()
                        except:
                            pass
                    auth[key_value[0].strip()] = value
            res.append(auth)

    return res


def get_inf_id(args):
    if len(args) >= 1:
        if args[0].isdigit():
            inf_id = int(args[0])
            return inf_id
        else:
            return args[0]
    else:
        raise Exception("Infrastructure ID not specified")


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


def main(operation, options, args, parser):
    """
    Launch Client
    """
    if (operation not in ["removeresource", "addresource", "create", "destroy", "getinfo", "list", "stop", "start",
                          "alter", "getcontmsg", "getvminfo", "reconfigure", "getradl", "getvmcontmsg", "stopvm",
                          "startvm", "sshvm", "getstate", "getversion", "export", "import"]):
        parser.error("operation not recognised.  Use --help to show all the available operations")

    if (operation not in ["getversion"]):
        if options.auth_file is None:
            parser.error("Auth file not specified")

        auth_data = read_auth_data(options.auth_file)

        if auth_data is None:
            parser.error("Auth file with incorrect format.")

    if options.xmlrpc.startswith("https"):
        print("Secure connection with: " + options.xmlrpc)
        if not options.verify:
            try:
                import ssl
                ssl._create_default_https_context = ssl._create_unverified_context
            except:
                pass
    else:
        print("Connected with: " + options.xmlrpc)

    server = ServerProxy(options.xmlrpc, allow_none=True)

    if operation == "removeresource":
        inf_id = get_inf_id(args)
        context = True
        if len(args) >= 2:
            vm_list = args[1]

            if len(args) >= 3:
                if args[2] in ["0", "1"]:
                    context = bool(int(args[2]))
                else:
                    print("The ctxt flag must be 0 or 1")
                    return False
        else:
            print("Coma separated VM list to remove not specified")
            return False

        (success, vms_id) = server.RemoveResource(inf_id, vm_list, auth_data, context)

        if success:
            print("Resources with IDs: %s successfully deleted." % str(vms_id))
        else:
            print("ERROR deleting resources from the infrastructure: %s" % vms_id)
            return False

    elif operation == "addresource":
        inf_id = get_inf_id(args)
        context = True
        if len(args) >= 2:
            if not os.path.isfile(args[1]):
                print("RADL file '" + args[1] + "' does not exist")
                return False

            if len(args) >= 3:
                if args[2] in ["0", "1"]:
                    context = bool(int(args[2]))
                else:
                    print("The ctxt flag must be 0 or 1")
                    return False
        else:
            print("RADL file to add resources not specified")
            return False

        radl = radl_parse.parse_radl(args[1])

        (success, vms_id) = server.AddResource(inf_id, str(radl), auth_data, context)

        if success:
            print("Resources with IDs: %s successfully added." % str(vms_id))
        else:
            print("ERROR adding resources to infrastructure: %s" % vms_id)
            return False

    elif operation == "create":
        if len(args) >= 1:
            if not os.path.isfile(args[0]):
                print("RADL file '" + args[0] + "' does not exist")
                return False
        else:
            print("RADL file to create inf. not specified")
            return False

        # Read the file
        f = open(args[0])
        radl_data = "".join(f.readlines())
        f.close()
        # check for input parameters @input.[param_name]@
        radl_data = get_input_params(radl_data)

        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        (success, inf_id) = server.CreateInfrastructure(str(radl), auth_data)

        if success:
            print("Infrastructure successfully created with ID: %s" % str(inf_id))
        else:
            print("ERROR creating the infrastructure: %s" % inf_id)
            return False

    elif operation == "alter":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to Modify not specified")
            return False
        if len(args) >= 3:
            if not os.path.isfile(args[2]):
                print("RADL file '" + args[2] + "' does not exist")
                return False
        else:
            print("RADL file to modify the VM not specified")
            return False

        radl = radl_parse.parse_radl(args[2])

        (success, res) = server.AlterVM(inf_id, vm_id, str(radl), auth_data)

        if success:
            print("VM successfully modified.")
        else:
            print("ERROR modifying the VM: %s" % res)
            return False

    elif operation == "reconfigure":
        inf_id = get_inf_id(args)
        radl = ""
        vm_list = None
        if len(args) >= 2:
            if not os.path.isfile(args[1]):
                print("RADL file '" + args[1] + "' does not exist")
                return False
            else:
                # Read the file
                f = open(args[1])
                radl_data = "".join(f.readlines())
                f.close()
                radl = radl_parse.parse_radl(radl_data)

                if len(args) >= 3:
                    vm_list = [int(vm_id) for vm_id in args[2].split(",")]

        (success, res) = server.Reconfigure(inf_id, str(radl), auth_data, vm_list)

        if success:
            print("Infrastructure successfully reconfigured.")
        else:
            print("ERROR reconfiguring the infrastructure: " + res)
            return False

    elif operation == "getcontmsg":
        inf_id = get_inf_id(args)

        (success, cont_out) = server.GetInfrastructureContMsg(inf_id, auth_data)
        if success:
            if len(cont_out) > 0:
                print("Msg Contextualizator: \n")
                print(cont_out)
            else:
                print("No Msg Contextualizator avaliable\n")
        else:
            print("Error getting infrastructure contextualization message: %s" % cont_out)

    elif operation == "getstate":
        inf_id = get_inf_id(args)

        (success, res) = server.GetInfrastructureState(inf_id, auth_data)
        if success:
            state = res['state']
            vm_states = res['vm_states']
            print("The infrastructure is in state: %s" % state)
            for vm_id, vm_state in vm_states.iteritems():
                print("VM ID: %s is in state: %s." % (vm_id, vm_state))
        else:
            print("Error getting infrastructure state: %s" % res)

    elif operation == "getvminfo":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to get info not specified")
            return False

        propiedad = None
        if len(args) >= 3:
            propiedad = args[2]

        if propiedad:
            (success, info) = server.GetVMProperty(inf_id, vm_id, propiedad, auth_data)
        else:
            (success, info) = server.GetVMInfo(inf_id, vm_id, auth_data)

        if not success:
            print("ERROR getting the VM info: %s" % vm_id)

        print(info)

    elif operation == "getinfo":
        inf_id = get_inf_id(args)
        propiedad = None
        if len(args) >= 2:
            propiedad = args[1]

        (success, vm_ids) = server.GetInfrastructureInfo(inf_id, auth_data)

        if success:
            for vm_id in vm_ids:
                print("Info about VM with ID: %s" % vm_id)

                if propiedad:
                    (success, info) = server.GetVMProperty(inf_id, vm_id, propiedad, auth_data)
                else:
                    (success, info) = server.GetVMInfo(inf_id, vm_id, auth_data)

                if not success:
                    print("ERROR getting the information about the VM: " + vm_id)

                print(info)
        else:
            print("ERROR getting the information about the infrastructure: " + str(vm_ids))
            return False

    elif operation == "destroy":
        inf_id = get_inf_id(args)
        (success, inf_id) = server.DestroyInfrastructure(inf_id, auth_data)

        if success:
            print("Infrastructure successfully destroyed")
        else:
            print("ERROR destroying the infrastructure: %s" % inf_id)
            return False

    elif operation == "list":
        (success, res) = server.GetInfrastructureList(auth_data)

        if success:
            if res:
                print("Infrastructure IDs: \n  %s" % ("\n  ".join([str(inf_id) for inf_id in res])))
            else:
                print("No Infrastructures.")
        else:
            print("ERROR listing then infrastructures: %s" % res)
            return False

    elif operation == "start":
        inf_id = get_inf_id(args)
        (success, inf_id) = server.StartInfrastructure(inf_id, auth_data)

        if success:
            print("Infrastructure successfully started")
        else:
            print("ERROR starting the infraestructure: " + inf_id)
            return False

    elif operation == "stop":
        inf_id = get_inf_id(args)
        (success, inf_id) = server.StopInfrastructure(inf_id, auth_data)

        if success:
            print("Infrastructure successfully stopped")
        else:
            print("ERROR stopping the infrastructure: " + inf_id)
            return False

    elif operation == "getradl":
        inf_id = get_inf_id(args)
        (success, radl) = server.GetInfrastructureRADL(inf_id, auth_data)

        if success:
            print(radl)
        else:
            print("ERROR getting the infrastructure RADL: %s" % inf_id)
            return False

    elif operation == "getvmcontmsg":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to get info not specified")
            return False

        (success, info) = server.GetVMContMsg(inf_id, vm_id, auth_data)

        if success:
            print(info)
        else:
            print("Error getting VM contextualization message: %s" % info)
            return False

    elif operation == "startvm":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to get info not specified")
            return False

        (success, info) = server.StartVM(inf_id, vm_id, auth_data)

        if success:
            print("VM successfully started")
        else:
            print("Error starting VM: %s" % info)
            return False

    elif operation == "stopvm":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to get info not specified")
            return False

        (success, info) = server.StopVM(inf_id, vm_id, auth_data)

        if success:
            print("VM successfully stopped")
        else:
            print("Error stopping VM: %s" % info)
            return False

    elif operation == "sshvm":
        inf_id = get_inf_id(args)
        if len(args) >= 2:
            vm_id = args[1]
        else:
            print("VM ID to get info not specified")
            return False

        (success, info) = server.GetVMInfo(inf_id, vm_id, auth_data)

        if success:
            try:
                radl = radl_parse.parse_radl(info)
                CmdSsh.run(radl)
            except Exception as ex:
                print(str(ex))
                return False
        else:
            print("Error accessing VM: %s" % info)
            return False

    elif operation == "getversion":
        (success, version) = server.GetVersion()

        if success:
            print("IM service version: %s" % version)
        else:
            print("ERROR getting IM service version: " + version)
            return False

    elif operation == "export":
        inf_id = get_inf_id(args)
        delete = False
        if len(args) >= 2:
            delete = bool(int(args[1]))

        (success, data) = server.ExportInfrastructure(inf_id, delete, auth_data)

        if success:
            print(data)
        else:
            print("ERROR getting IM service version: " + data)
            return False

    elif operation == "import":
        if len(args) >= 1:
            if not os.path.isfile(args[0]):
                print("JSON file '" + args[0] + "' does not exist")
                return False
        else:
            print("JSON file to create inf. not specified")
            return False

        f = open(args[0])
        data = "".join(f.readlines())
        f.close()

        (success, inf_id) = server.ImportInfrastructure(data, auth_data)

        if success:
            print("New Inf: " + inf_id)
        else:
            print("ERROR getting IM service version: " + inf_id)
            return False


def get_parser():
    """
    Get Client parser
    """

    config = ConfigParser.RawConfigParser()
    config.read(['im_client.cfg', os.path.expanduser('~/.im_client.cfg')])

    default_auth_file = None
    default_xmlrpc = "http://localhost:8899"
    XMLRCP_SSL_CA_CERTS = "./pki/ca-chain.pem"

    if config.has_option('im_client', "auth_file"):
        default_auth_file = config.get('im_client', "auth_file")
    if config.has_option('im_client', "xmlrpc_url"):
        default_xmlrpc = config.get('im_client', "xmlrpc_url")
    if config.has_option('im_client', "xmlrpc_ssl_ca_certs"):
        XMLRCP_SSL_CA_CERTS = config.get('im_client', "xmlrpc_ssl_ca_certs")

    NOTICE = "\n\n\
IM - Infrastructure Manager\n\
Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia\n\
This program comes with ABSOLUTELY NO WARRANTY; for details please\n\
read the terms at http://www.gnu.org/licenses/gpl-3.0.txt.\n\
This is free software, and you are welcome to redistribute it\n\
under certain conditions; please read the license at \n\
http://www.gnu.org/licenses/gpl-3.0.txt for details."

    parser = PosOptionParser(usage="%prog [-u|--xmlrpc-url <url>] [-v|--verify-ssl] [-a|--auth_file <filename>] "
                             "operation op_parameters" + NOTICE, version="%prog " + __version__)
    parser.add_option("-a", "--auth_file", dest="auth_file", nargs=1, default=default_auth_file, help="Authentication"
                      " data file", type="string")
    parser.add_option("-u", "--xmlrpc-url", dest="xmlrpc", nargs=1, default=default_xmlrpc, help="URL address of the "
                      "InfrastructureManager XML-RCP daemon", type="string")
    parser.add_option("-v", "--verify-ssl", action="store_true", dest="verify", help="Verify the certificate of the "
                      "InfrastructureManager XML-RCP server")
    parser.add_operation_help('list', '')
    parser.add_operation_help('create', '<radl_file>')
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
    parser.add_operation_help('sshvm', '<inf_id> <vm_id>')
    parser.add_operation_help('export', '<inf_id> [delete]')
    parser.add_operation_help('import', '<json_file>')
    parser.add_operation_help('getversion', '')

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
