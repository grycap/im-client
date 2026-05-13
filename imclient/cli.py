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

import os
import sys
import json
import configparser as ConfigParser

from imclient import IMClient, version
from imclient.imclient import CmdSsh, CmdScp, PosOptionParser


def main(operation, options, args, parser):
    """
    Launch Client
    """
    if options.restapi is None:
        options.restapi = "http://localhost:8800"

    if (operation not in ["removeresource", "addresource", "create", "destroy", "getinfo", "list", "stop", "start",
                          "alter", "getcontmsg", "getvminfo", "reconfigure", "getradl", "getvmcontmsg", "stopvm",
                          "startvm", "sshvm", "ssh", "getstate", "getversion", "export", "import", "getoutputs",
                          "rebootvm", "cloudusage", "cloudimages", "wait", "create_wait_outputs", "change_auth",
                          "putvm", "put", "getvm", "get"]):
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
        if options.restapi.startswith("https"):
            print("Secure connection with: " + options.restapi)
        else:
            print("Connected with: " + options.restapi)

    if operation == "removeresource":
        try:
            vms_id = imclient._removeresource()
            if not options.quiet:
                print("Resources with IDs: %s successfully deleted." % ",".join(str(v) for v in vms_id))
            return True
        except Exception as ex:
            print("ERROR deleting resources from the infrastructure: %s" % ex)
            return False

    elif operation == "addresource":
        try:
            vms_id = imclient._addresource()
            if not options.quiet:
                print("Resources with IDs: %s successfully added." % ",".join(str(v) for v in vms_id))
            else:
                print(json.dumps(vms_id, indent=4))
            return True
        except Exception as ex:
            print("ERROR adding resources to infrastructure: %s" % ex)
            return False

    elif operation == "create":
        try:
            inf_id = imclient._create()
            if not options.quiet:
                print("Infrastructure successfully created with ID: %s" % str(inf_id))
            return True
        except Exception as ex:
            if not options.quiet:
                print("ERROR creating the infrastructure: %s" % str(ex))
            return False

    elif operation == "alter":
        try:
            imclient._alter()
            if not options.quiet:
                print("VM successfully modified.")
            return True
        except Exception as ex:
            print("ERROR modifying the VM: %s" % ex)
            return False

    elif operation == "reconfigure":
        try:
            imclient._reconfigure()
            if not options.quiet:
                print("Infrastructure successfully reconfigured.")
            return True
        except Exception as ex:
            print("ERROR reconfiguring the infrastructure: %s" % ex)
            return False

    elif operation == "getcontmsg":
        try:
            cont_out = imclient._get_infra_property("contmsg")
            if len(cont_out) > 0:
                if not options.quiet:
                    print("Msg Contextualizator: \n")
                print(cont_out)
            elif not options.quiet:
                print("No Msg Contextualizator avaliable\n")
            return True
        except Exception as ex:
            print("Error getting infrastructure contextualization message: %s" % ex)
            return False

    elif operation == "getstate":
        try:
            res = imclient._get_infra_property("state")
            if not options.quiet:
                state = res['state']
                vm_states = res['vm_states']
                print("The infrastructure is in state: %s" % state)
                for vm_id, vm_state in vm_states.items():
                    print("VM ID: %s is in state: %s." % (vm_id, vm_state))
            else:
                print(json.dumps(res, indent=4))
            return True
        except Exception as ex:
            print("Error getting infrastructure state: %s" % ex)
            return False

    elif operation == "getvminfo":
        try:
            info = imclient._getvminfo()
            print(info)
            return True
        except Exception as ex:
            print("ERROR getting the VM info: %s" % ex)
            return False

    elif operation == "getinfo":
        try:
            vms_info = imclient._getinfo()
            for vm_id, vm_radl in vms_info:
                if not options.quiet:
                    print("Info about VM with ID: %s" % vm_id)
                if vm_radl is not None:
                    if not options.system_name or (options.system_name and vm_radl != ""):
                        print(vm_radl)
                else:
                    print("ERROR getting the information about the VM %s" % vm_id)
            return True
        except Exception as ex:
            print("ERROR getting the information about infrastructure: %s" % ex)
            return False

    elif operation == "destroy":
        try:
            imclient._destroy()
            if not options.quiet:
                print("Infrastructure successfully destroyed")
            return True
        except ValueError as ex:
            print(str(ex))
            return False
        except Exception as ex:
            print("ERROR destroying the infrastructure: %s" % ex)
            return False

    elif operation == "list":
        try:
            res = imclient._list_infras(show_name=options.name)
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
            return True
        except Exception as ex:
            print("ERROR listing then infrastructures: %s" % ex)
            return False

    elif operation == "start":
        try:
            imclient._infra_op(operation)
            if not options.quiet:
                print("Infrastructure successfully started")
            return True
        except Exception as ex:
            print("ERROR starting the infraestructure: %s" % ex)
            return False

    elif operation == "stop":
        try:
            imclient._infra_op(operation)
            if not options.quiet:
                print("Infrastructure successfully stopped")
            return True
        except Exception as ex:
            print("ERROR stopping the infrastructure: %s" % ex)
            return False

    elif operation == "getradl":
        try:
            radl = imclient._get_infra_property("radl")
            print(radl)
            return True
        except Exception as ex:
            print("ERROR getting the infrastructure RADL: %s" % ex)
            return False

    elif operation == "getvmcontmsg":
        try:
            info = imclient._getvmcontmsg()
            print(info)
            return True
        except Exception as ex:
            print("Error getting VM contextualization message: %s" % ex)
            return False

    elif operation == "startvm":
        try:
            imclient._vm_op("start")
            if not options.quiet:
                print("VM successfully started")
            return True
        except Exception as ex:
            print("Error starting VM: %s" % ex)
            return False

    elif operation == "stopvm":
        try:
            imclient._vm_op("stop")
            if not options.quiet:
                print("VM successfully stopped")
            return True
        except Exception as ex:
            print("Error stopping VM: %s" % ex)
            return False

    elif operation == "rebootvm":
        try:
            imclient._vm_op("reboot")
            if not options.quiet:
                print("VM successfully rebooted")
            return True
        except Exception as ex:
            print("Error rebooting VM: %s" % ex)
            return False

    elif operation in ["sshvm", "ssh"]:
        try:
            radl, show_only, cmd = imclient._ssh(operation)
            CmdSsh.run(radl, show_only, cmd)
            return True
        except Exception as ex:
            print(str(ex))
            return False

    elif operation in ["putvm", "put"]:
        try:
            radl, show_only, cmd = imclient._ssh(operation)
            if len(cmd) != 2:
                print("put must have 2 arguments")
                return False
            CmdScp.run(radl, "put", cmd, show_only)
            return True
        except Exception as ex:
            print(str(ex))
            return False

    elif operation in ["getvm", "get"]:
        try:
            radl, show_only, cmd = imclient._ssh(operation)
            if len(cmd) != 2:
                print("get must have 2 arguments")
                return False
            CmdScp.run(radl, "get", cmd, show_only)
            return True
        except Exception as ex:
            print(str(ex))
            return False

    elif operation == "getversion":
        try:
            ver = imclient.getversion()
            if not options.quiet:
                print("IM service version: %s" % ver)
            else:
                print(ver)
            return True
        except Exception as ex:
            print("ERROR getting IM service version: %s" % ex)
            return False

    elif operation == "export":
        try:
            data = imclient._export_data()
            print(json.dumps(data, indent=4))
            return True
        except Exception as ex:
            print("ERROR exporting data: %s" % ex)
            return False

    elif operation == "import":
        try:
            inf_id = imclient._import_data()
            if not options.quiet:
                print("New Inf: " + inf_id)
            else:
                print(inf_id)
            return True
        except Exception as ex:
            print("ERROR importing data: %s" % ex)
            return False

    elif operation == "getoutputs":
        try:
            outputs = imclient._get_infra_property("outputs")
            if not options.quiet:
                print("The infrastructure outputs:\n")
                for key, value in outputs.items():
                    print("%s = %s" % (key, value))
            else:
                print(json.dumps(outputs, indent=4))
            return True
        except Exception as ex:
            print("ERROR getting outputs: %s" % ex)
            return False

    elif operation == "cloudimages":
        try:
            data = imclient._get_cloud_info("images")
            print(json.dumps(data, indent=4))
            return True
        except Exception as ex:
            print("ERROR getting cloud image list: %s" % ex)
            return False

    elif operation == "cloudusage":
        try:
            data = imclient._get_cloud_info("quotas")
            print(json.dumps(data, indent=4))
            return True
        except Exception as ex:
            print("ERROR getting cloud usage: %s" % ex)
            return False

    elif operation == "wait":
        try:
            info = imclient._wait()
            if not options.quiet:
                print(info)
            return True
        except Exception as ex:
            print(str(ex))
            return False

    elif operation == "create_wait_outputs":
        try:
            inf_id = imclient._create()
            imclient.args = [inf_id]
            imclient._wait()
            outputs = imclient.get_infra_property(inf_id, "outputs")
            outputs["infid"] = inf_id
            print(json.dumps(outputs))
            return True
        except Exception as ex:
            print(json.dumps({'error': str(ex)}))
            return False

    elif operation == "change_auth":
        try:
            imclient._change_auth()
            if not options.quiet:
                print("Auth data successfully changed.")
            return True
        except Exception as ex:
            print("ERROR changing auth data: %s" % ex)
            return False


def get_parser():
    """
    Get Client parser
    """

    config = ConfigParser.RawConfigParser()
    config.read(['im_client.cfg', os.path.expanduser('~/.im_client.cfg')])

    default_auth_file = None
    default_restapi = None

    if config.has_option('im_client', "auth_file"):
        default_auth_file = config.get('im_client', "auth_file")
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

    parser = PosOptionParser(usage="%prog [-r|--restapi-url <url>] [-v|--verify-ssl] "
                             "[-a|--auth_file <filename>] operation op_parameters" + NOTICE, version=version)
    parser.add_option("-a", "--auth_file", dest="auth_file", nargs=1, default=default_auth_file, help="Authentication"
                      " data file", type="string")
    parser.add_option("-r", "--rest-url", dest="restapi", nargs=1, default=default_restapi, help="URL address of the "
                      "InfrastructureManager REST API", type="string")
    parser.add_option("-v", "--verify-ssl", action="store_true", default=False, dest="verify",
                      help="Verify the certificate of the InfrastructureManager REST API server")
    parser.add_option("-f", "--force", action="store_true", default=False, dest="force",
                      help="Force the deletion of the infrastructure")
    parser.add_option("-q", "--quiet", action="store_true", default=False, dest="quiet",
                      help="Work in quiet mode")
    parser.add_option("-n", "--name", action="store_true", default=False, dest="name",
                      help="Use infrastructure name instead of ID")
    parser.add_option("-s", "--system_name", default=None, dest="system_name", nargs=1, type="string",
                      help="Filter VMs by system name")
    parser.add_option("-y", "--yes", action="store_true", default=False, dest="yes",
                      help="Do not ask for confirmation when performing operations that may cause data loss")
    parser.add_operation_help('list', '')
    parser.add_operation_help('create', '<radl_file> [async_flag]')
    parser.add_operation_help('destroy', '<inf_id> [force_option] [yes_option]')
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
    parser.add_operation_help('sshvm', '<inf_id> <vm_id> [show_only] [cmd]')
    parser.add_operation_help('ssh', '<inf_id> [show_only] [cmd]')
    parser.add_operation_help('getvm', '<inf_id> <vm_id> <show_only> <orig> <dest>')
    parser.add_operation_help('get', '<inf_id> <show_only> <orig> <dest>')
    parser.add_operation_help('putvm', '<inf_id> <vm_id> <show_only> <orig> <dest>')
    parser.add_operation_help('put', '<inf_id> <show_only> <orig> <dest>')
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


def client():
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


if __name__ == "__main__":
    client()
