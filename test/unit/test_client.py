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

import unittest
import sys
import os
import json
from io import StringIO

sys.path.append("..")
sys.path.append(".")

from imclient import IMClient
from imclient.cli import main, get_parser
from mock import patch, MagicMock
from urllib.parse import urlparse


def get_abs_path(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(tests_path, file_name)


class TestClient(unittest.TestCase):
    """
    Class to test the IM client
    """

    @staticmethod
    def get_response(method, url, verify, cert=None, headers=None, data=None, params=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        if method == "GET":
            if url == "/infrastructures":
                resp.status_code = 200
                resp.text = ('{ "uri-list": [ { "uri" : "http://localhost/inf1" },'
                             '{ "uri" : "http://localhost/inf2"}]}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/contmsg":
                resp.status_code = 200
                resp.json.return_value = {"contmsg": "contmsg"}
            elif url in ["/infrastructures/infid/outputs", "/infrastructures/inf1/outputs"]:
                resp.status_code = 200
                resp.text = '{"outputs": {"output1": "value1", "output2": "value2"}}'
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/state":
                resp.status_code = 200
                resp.text = '{"state": {"state": "running", "vm_states": {"vm1": "running"}}}'
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/inf1/state":
                resp.status_code = 200
                resp.text = '{"state": {"state": "configured", "vm_states": {"vm1": "configured"}}}'
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/vms/vmid":
                resp.status_code = 200
                resp.text = "radltest"
            elif url == "/infrastructures/infid":
                resp.status_code = 200
                resp.text = ('{ "uri-list": [{ "uri" : "http://localhost/infid/vms/vm1" }]}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid2":
                resp.status_code = 200
                resp.text = ('{ "uri-list": [{ "uri" : "http://localhost/infid2/vms/vm1" },'
                             '{ "uri" : "http://localhost/infid2/vms/vm2" }]}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/vms/vm1":
                resp.status_code = 200
                resp.text = "radltest"
            elif url == "/infrastructures/infid2/vms/vm1":
                resp.status_code = 200
                resp.text = "system node (cpu.count = 1)"
            elif url == "/infrastructures/infid2/vms/vm2":
                resp.status_code = 200
                resp.text = "system node2 (cpu.count = 2)"
            elif url == "/infrastructures/inf1/radl":
                resp.status_code = 200
                resp.json.return_value = {"radl": "description desc (name = 'some name')\nsystem s1 ()"}
            elif url == "/infrastructures/inf2/radl":
                resp.status_code = 200
                resp.json.return_value = {"radl": "description desc (name = 'some name2')\nsystem s2 ()"}
            elif url == "/infrastructures/infid/radl":
                resp.status_code = 200
                resp.json.return_value = {"radl": "radltest"}
            elif url in ["/infrastructures/infid/vms/vmid/contmsg", "/infrastructures/infid/vms/vm1/contmsg"]:
                resp.status_code = 200
                resp.text = 'getvmcontmsg'
            elif url == "/version":
                resp.status_code = 200
                resp.text = '1.0'
            elif url == "/infrastructures/infid/data":
                resp.status_code = 200
                resp.text = '{"data": "strinf"}'
                resp.json.return_value = json.loads(resp.text)
            elif url == "/clouds/one/quotas":
                resp.status_code = 200
                resp.text = ('{"quotas": {"cores": {"used": 5, "limit": -1}}}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/clouds/one/images":
                resp.status_code = 200
                resp.text = ('{"images": [{"uri": "one://oneserver/1","name": "image1"},'
                             '{"uri": "one://oneserver:2","name": "image2"}]}')
                resp.json.return_value = json.loads(resp.text)
            else:
                resp.status_code = 404
        elif method == "POST":
            if url == "/infrastructures":
                resp.status_code = 200
                resp.text = 'http://localhost/inf1'
            elif url == "/infrastructures/infid":
                resp.status_code = 200
                resp.text = ('{ "uri-list": [ { "uri" : "http://localhost/infid/vms/1" }]}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/authorization":
                resp.status_code = 200
                resp.text = ""
            else:
                resp.status_code = 404
        elif method == "DELETE":
            if url == "/infrastructures/infid/vms/1":
                resp.status_code = 200
                resp.text = ""
            elif url == "/infrastructures/infid":
                resp.status_code = 200
                resp.text = ""
            else:
                resp.status_code = 404
        elif method == "PUT":
            if url == "/infrastructures/infid/vms/vmid":
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/reconfigure':
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/start':
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/stop':
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/vms/vmid/start':
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/vms/vmid/stop':
                resp.status_code = 200
                resp.text = ""
            elif url == '/infrastructures/infid/vms/vmid/reboot':
                resp.status_code = 200
                resp.text = ""
            elif url == "/infrastructures":
                resp.status_code = 200
                resp.text = "newinfid"
            else:
                resp.status_code = 404
        else:
            resp.status_code = 404

        return resp

    @patch('requests.request')
    def test_list(self, requests):
        """
        Test list operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.verify = False
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("list", options, [], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        res = main("list", options, [".*hadoop.*"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

        options.name = True
        out = StringIO()
        sys.stdout = out
        res = main("list", options, [], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("inf1    some name", output)
        self.assertIn("inf2    some name2", output)
        sys.stdout = oldstdout
        options.name = False

    @patch('requests.request')
    def test_create(self, requests):
        """
        Test create operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("create", options, [get_abs_path("../files/test.radl")], parser)
        self.assertTrue(res)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully created with ID: inf1", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        res = main("create", options, [get_abs_path("../files/tosca.yml")], parser)
        self.assertIsNotNone(res)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully created with ID: inf1", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_removeresource(self, requests):
        """
        Test removeresource operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("removeresource", options, ["infid", "1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully deleted.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_addresource(self, requests):
        """
        Test addresource operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("addresource", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully added.", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        res = main("addresource", options, ["infid", get_abs_path("../files/tosca.yml")], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully added.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_alter(self, requests):
        """
        Test alter operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("alter", options, ["infid", "vmid", get_abs_path("../files/test.radl")], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully modified.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_reconfigure(self, requests):
        """
        Test reconfigure operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("reconfigure", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully reconfigured.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getcontmsg(self, requests):
        """
        Test getcontmsg operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getcontmsg", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Msg Contextualizator: \n\ncontmsg", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getstate(self, requests):
        """
        Test getstate operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getstate", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure is in state: running\nVM ID: vm1 is in state: running.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getvminfo(self, requests):
        """
        Test getvminfo operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getvminfo", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getinfo(self, requests):
        """
        Test getinfo operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        options.system_name = None
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getinfo", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\nradltest", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        res = main("getinfo", options, ["infid", "contmsg"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\ngetvmcontmsg", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.system_name = "node"
        res = main("getinfo", options, ["infid2", "cpu.count"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\n1", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch('builtins.input', return_value='yes')
    def test_destroy(self, input_mock, requests):
        """
        Test destroy operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        options.force = False
        options.yes = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("destroy", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.force = True
        res = main("destroy", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

        input_mock.return_value = "a"
        out = StringIO()
        sys.stdout = out
        options.yes = False
        options.force = True
        res = main("destroy", options, ["infid"], parser)
        self.assertEqual(res, False)
        output = out.getvalue().strip()
        self.assertIn("Canceled by the user", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.yes = True
        options.force = False
        res = main("destroy", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_start(self, requests):
        """
        Test start operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("start", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully started", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_stop(self, requests):
        """
        Test stop operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("stop", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully stopped", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getradl(self, requests):
        """
        Test getradl operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getradl", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getvmcontmsg(self, requests):
        """
        Test getvmcontmsg operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getvmcontmsg", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("getvmcontmsg", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_startvm(self, requests):
        """
        Test startvm operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.quiet = False
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("startvm", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully started", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_stopvm(self, requests):
        """
        Test stopvm operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("stopvm", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully stopped", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_rebootvm(self, requests):
        """
        Test rebootvm operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("rebootvm", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully rebooted", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getversion(self, requests):
        """
        Test getversion operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getversion", options, [], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("1.0", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_export(self, requests):
        """
        Test export operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("export", options, ["infid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("strinf", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_import(self, requests):
        """
        Test import operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("import", options, [get_abs_path("../files/test.radl")], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("New Inf: newinfid", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_sshvm(self, requests):
        """
        Test sshvm operation
        """
        radl = open(get_abs_path("../files/test.radl"), 'r').read()

        def get_ssh_response(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = radl
            return resp

        requests.side_effect = get_ssh_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

        sys.stdout = out
        sys.stderr = out
        res = main("ssh", options, ["infid", "1", "cmd", "cmd_args"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1 cmd cmd_args", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

        # test proxy host
        radl_proxy = open(get_abs_path("../files/test_proxy.radl"), 'r').read()

        def get_proxy_response(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = radl_proxy
            return resp

        requests.side_effect = get_proxy_response

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 22 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "-o 'ProxyCommand=sshpass -p passwd ssh -W %h:%p -p 22"
                      " -o StrictHostKeyChecking=no username@someserver.com' ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    @patch('requests.request')
    def test_scpvm(self, requests):
        """
        Test scpvm operation
        """
        radl = open(get_abs_path("../files/test.radl"), 'r').read()

        def get_ssh_response(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = radl
            return resp

        requests.side_effect = get_ssh_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("getvm", options, ["infid", "vmid", "1", "orig", "dest"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo scp -r -P 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1:orig dest", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("putvm", options, ["infid", "vmid", "1", "orig", "dest"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo scp -r -P 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "orig ubuntu@10.0.0.1:dest", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    @patch('requests.request')
    def test_sshvm_key(self, requests):
        """
        Test sshvm operation
        """
        radl = open(get_abs_path("../files/test_priv.radl"), 'r').read()

        def get_ssh_response(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = radl
            return resp

        requests.side_effect = get_ssh_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("ssh -p 1022 -i /tmp/", output)
        self.assertIn(" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    @patch('requests.request')
    def test_sshvm_via_master(self, requests):
        """
        Test sshvm operation via master VM
        """
        radl_master = open(get_abs_path("../files/test_ssh_master.radl"), 'r').read()
        radl_wn = open(get_abs_path("../files/test_ssh_wn.radl"), 'r').read()
        radl_iter = iter([radl_wn, radl_master])

        def get_ssh_response(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = next(radl_iter)
            return resp

        requests.side_effect = get_ssh_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("ssh -p 22 -i /tmp/", output)
        self.assertIn(" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
                      " -o 'ProxyCommand=ssh -W %h:%p -i /var/tmp/ubuntu_ubuntu_10.0.0.2.pem -p 22"
                      " -o StrictHostKeyChecking=no ubuntu@8.8.8.8' ubuntu@10.0.0.2", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    def test_parser(self):
        """
        Test parser
        """
        parser = get_parser()
        (_, args) = parser.parse_args(["create", "test.radl"])
        self.assertEqual(['create', 'test.radl'], args)

    @patch('requests.request')
    def test_getoutputs(self, requests):
        """
        Test getoutputs operation
        """
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        oldstdout = sys.stdout
        out = StringIO()
        sys.stdout = out
        options.quiet = False
        options.xmlrpc = None
        options.name = False
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getoutputs", options, ["infid", "vmid"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure outputs:\n", output)
        self.assertIn("\noutput2 = value2", output)
        self.assertIn("\noutput1 = value1", output)
        sys.stdout = oldstdout

    @patch("imclient.imclient.OptionParser.exit")
    def test_parser_help(self, option_parser_exit):
        """
        Test parser help
        """
        option_parser_exit.return_value = True
        parser = get_parser()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        parser.parse_args(["--help"])
        output = out.getvalue().strip()
        self.assertEqual(output[:7], "Usage: ")
        self.assertIn("[-r|--restapi-url <url>] [-v|--verify-ssl] "
                      "[-a|--auth_file <filename>] operation op_parameters", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getcloudimages(self, requests):
        """
        Test cloudimages operation
        """
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        oldstdout = sys.stdout
        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.quiet = False
        options.name = False
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response

        res = main("cloudimages", options, ["one"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn('"uri": "one://oneserver/1"', output)
        self.assertIn('"name": "image1"', output)
        self.assertIn('"uri": "one://oneserver:2"', output)
        self.assertIn('"name": "image2"', output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_getcloudusage(self, requests):
        """
        Test cloudusage operation
        """
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        oldstdout = sys.stdout
        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.quiet = True
        options.name = False
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response

        res = main("cloudusage", options, ["one"], parser)
        self.assertEqual(res, True)
        output = json.loads(out.getvalue().strip())
        self.assertEqual({'cores': {'used': 5, 'limit': -1}}, output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_wait(self, requests):
        """
        Test wait operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("wait", options, ["inf1"], parser)
        self.assertEqual(res, True)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure is in state: configured", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_create_wait_outputs(self, requests):
        """
        Test create_wait_outputs operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.xmlrpc = None
        options.quiet = True
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("create_wait_outputs", options, [get_abs_path("../files/test.radl")], parser)
        self.assertEqual(res, True)
        output = json.loads(out.getvalue().strip())
        self.assertEqual(output, {"infid": "inf1", "output1": "value1", "output2": "value2"})
        sys.stdout = oldstdout

    @patch('requests.request')
    def test_change_user(self, requests):
        """
        Test create_wait_outputs operation
        """
        requests.side_effect = self.get_response
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = "https://localhost:8800"
        options.xmlrpc = None
        options.quiet = True
        options.name = False
        parser = MagicMock()

        res = main("change_auth", options, ["infid", get_abs_path("../files/auth_new.dat")], parser)
        self.assertEqual(res, True)

    def test_read_auth_data(self):
        """
        Test read_auth_data function
        """
        auth_lines = ["""id = a1; type = InfrastructureManager; username = someuser; password = somepass """,
                      """id = a2; type = VMRC; username = someuser; password = somepass; """,
                      """id = a3; type = OpenNebula; username = someuser; password   =   "some;'pass" """,
                      """id = a4; type = EC2; username =someuser; password='some;"pass' """]
        auth = IMClient.read_auth_data(auth_lines)
        self.assertEqual(auth, [{'id': 'a1', 'password': "somepass",
                                 'type': 'InfrastructureManager', 'username': 'someuser'},
                                {'id': 'a2', 'password': "somepass",
                                 'type': 'VMRC', 'username': 'someuser'},
                                {'id': 'a3', 'password': "some;'pass",
                                 'type': 'OpenNebula', 'username': 'someuser'},
                                {'id': 'a4', 'password': 'some;"pass',
                                 'type': 'EC2', 'username': 'someuser'}])

    def test_init_client(self):
        """
        Test IMClient as a lib
        """
        auth_lines = ["""id = a1; type = InfrastructureManager; username = someuser; password = somepass """,
                      """id = a2; type = VMRC; username = someuser; password = somepass; """,
                      """id = a3; type = OpenNebula; username = someuser; password   =   "some;'pass" """,
                      """id = a4; type = EC2; username =someuser; password='some;"pass' """]
        auth = IMClient.read_auth_data(auth_lines)
        client = IMClient.init_client("https://im.egi.eu/im", auth)
        self.assertEqual(client.options.restapi, "https://im.egi.eu/im")
        self.assertEqual(client.options.verify, False)


if __name__ == '__main__':
    unittest.main()
