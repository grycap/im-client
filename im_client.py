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
    if options.xmlrpc:
        options.restapi = None
    elif options.restapi is None:
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
        url = options.restapi if options.restapi else options.xmlrpc
        if url.startswith("https"):
            print("Secure connection with: " + url)
        else:
            print("Connected with: " + url)

    if operation == "removeresource":
        success, vms_id = imclient._removeresource()
        if success:
            if not options.quiet:
                print("Resources with IDs: %s successfully deleted." % str(vms_id))
        else:
            print("ERROR deleting resources from the infrastructure: %s" % vms_id)
        return success

    elif operation == "addresource":
        success, vms_id = imclient._addresource()
        if success:
            if not options.quiet:
                print("Resources with IDs: %s successfully added." % ",".join(vms_id))
            else:
                print(json.dumps(vms_id, indent=4))
        else:
            print("ERROR adding resources to infrastructure: %s" % vms_id)
        return success

    elif operation == "create":
        success, inf_id = imclient._create()
        if success:
            if not options.quiet:
                print("Infrastructure successfully created with ID: %s" % str(inf_id))
        else:
            if not options.quiet:
                print("ERROR creating the infrastructure: %s" % inf_id)
        return success

    elif operation == "alter":
        success, res = imclient._alter()
        if success:
            if not options.quiet:
                print("VM successfully modified.")
        else:
            print("ERROR modifying the VM: %s" % res)
        return success

    elif operation == "reconfigure":
        success, res = imclient._reconfigure()
        if success:
            if not options.quiet:
                print("Infrastructure successfully reconfigured.")
        else:
            print("ERROR reconfiguring the infrastructure: " + res)
        return success

    elif operation == "getcontmsg":
        success, cont_out = imclient._get_infra_property("contmsg")
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
        success, res = imclient._get_infra_property("state")
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
        success, info = imclient._getvminfo()
        if not success:
            print("ERROR getting the VM info: %s" % info)
        print(info)
        return success

    elif operation == "getinfo":
        success, vms_info = imclient._getinfo()
        if success:
            for vm_id, vm_succes, vm_radl in vms_info:
                if not options.quiet:
                    print("Info about VM with ID: %s" % vm_id)
                if vm_succes:
                    if not options.system_name or (options.system_name and vm_radl != ""):
                        print(vm_radl)
                else:
                    print("ERROR getting the information about the VM: " + vm_radl)
        else:
            print("ERROR getting the information about infrastructure: " + vms_info)
        return success

    elif operation == "destroy":
        success, res = imclient._destroy()
        if success:
            if not options.quiet:
                print("Infrastructure successfully destroyed")
        else:
            print("ERROR destroying the infrastructure: %s" % res)
        return success

    elif operation == "list":
        success, res = imclient._list_infras(show_name=options.name)
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
        success, res = imclient._infra_op(operation)
        if success:
            if not options.quiet:
                print("Infrastructure successfully started")
        else:
            print("ERROR starting the infraestructure: " + res)
        return success

    elif operation == "stop":
        success, res = imclient._infra_op(operation)
        if success:
            if not options.quiet:
                print("Infrastructure successfully stopped")
        else:
            print("ERROR stopping the infrastructure: " + res)
        return success

    elif operation == "getradl":
        success, radl = imclient._get_infra_property("radl")
        if success:
            print(radl)
        else:
            print("ERROR getting the infrastructure RADL: %s" % radl)
        return success

    elif operation == "getvmcontmsg":
        success, info = imclient._getvmcontmsg()
        if success:
            print(info)
        else:
            print("Error getting VM contextualization message: %s" % info)
        return success

    elif operation == "startvm":
        success, info = imclient._vm_op("start")
        if success:
            if not options.quiet:
                print("VM successfully started")
        else:
            print("Error starting VM: %s" % info)

        return success

    elif operation == "stopvm":
        success, info = imclient._vm_op("stop")
        if success:
            if not options.quiet:
                print("VM successfully stopped")
        else:
            print("Error stopping VM: %s" % info)
        return success

    elif operation == "rebootvm":
        success, info = imclient._vm_op("reboot")
        if success:
            if not options.quiet:
                print("VM successfully rebooted")
        else:
            print("Error rebooting VM: %s" % info)
        return success

    elif operation in ["sshvm", "ssh"]:
        success, res = imclient._ssh(operation)
        if success:
            try:
                radl, show_only, cmd = res
                CmdSsh.run(radl, show_only, cmd)
            except Exception as ex:
                print(str(ex))
                return False
            return True
        else:
            print(res)
            return False

    elif operation in ["putvm", "put"]:
        success, res = imclient._ssh(operation)
        if success:
            try:
                radl, show_only, cmd = res
                if len(cmd) != 2:
                    print("put must have 2 arguments")
                    return False
                CmdScp.run(radl, "put", cmd, show_only)
            except Exception as ex:
                print(str(ex))
                return False
            return True
        else:
            print(res)
            return False

    elif operation in ["getvm", "get"]:
        success, res = imclient._ssh(operation)
        if success:
            try:
                radl, show_only, cmd = res
                if len(cmd) != 2:
                    print("get must have 2 arguments")
                    return False
                CmdScp.run(radl, "get", cmd, show_only)
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
        success, data = imclient._export_data()
        if success:
            print(data)
        else:
            print("ERROR exporting data: " + data)
        return success

    elif operation == "import":
        success, inf_id = imclient._import_data()
        if success:
            if not options.quiet:
                print("New Inf: " + inf_id)
            else:
                print(inf_id)
        else:
            print("ERROR importing data: " + inf_id)
        return success

    elif operation == "getoutputs":
        success, outputs = imclient._get_infra_property("outputs")
        if success:
            if not options.quiet:
                print("The infrastructure outputs:\n")
                for key, value in outputs.items():
                    print("%s = %s" % (key, value))
            else:
                print(json.dumps(outputs, indent=4))
        return success

    elif operation == "cloudimages":
        success, data = imclient._get_cloud_info("images")
        if success:
            print(json.dumps(data, indent=4))
        else:
            print("ERROR getting cloud image list: " + data)
        return success

    elif operation == "cloudusage":
        success, data = imclient._get_cloud_info("quotas")
        if success:
            print(json.dumps(data, indent=4))
        else:
            print("ERROR getting cloud usage: " + data)
        return success

    elif operation == "wait":
        success, info = imclient._wait()
        if success:
            if not options.quiet:
                print(info)
        else:
            print(info)
        return success

    elif operation == "create_wait_outputs":
        success, inf_id = imclient._create()
        if not success:
            print(json.dumps({'error': inf_id}))
            return False
        imclient.args = [inf_id]
        success, error = imclient._wait()
        if not success:
            print(json.dumps({'error': error, 'infid': inf_id}))
            return False
        success, outputs = imclient._get_infra_property("outputs")
        if success:
            outputs["infid"] = inf_id
            print(json.dumps(outputs))
        else:
            print('{"infid": "%s", "outputs": {}}' % inf_id)
        return True

    elif operation == "change_auth":
        success, error = imclient._change_auth()
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
                             "[-a|--auth_file <filename>] operation op_parameters" + NOTICE, version=version)
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
                      help="Use infrastructure name instead of ID")
    parser.add_option("-s", "--system_name", default=None, dest="system_name", nargs=1, type="string",
                      help="Filter VMs by system name")
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
