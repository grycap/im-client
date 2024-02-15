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
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

sys.path.append("..")
sys.path.append(".")

from imclient import IMClient
from im_client import main, get_parser
from mock import patch, MagicMock

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


def get_abs_path(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(tests_path, file_name)


class TestClient(unittest.TestCase):
    """
    Class to test the IM client
    """

    @staticmethod
    def get_response(method, url, verify, cert=None, headers=None, data=None):
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
                resp.text = ('{ "uri-list": [ { "uri" : "http://localhost/infid/vms/vm1" }]}')
                resp.json.return_value = json.loads(resp.text)
            elif url == "/infrastructures/infid/vms/vm1":
                resp.status_code = 200
                resp.text = "radltest"
            elif url == "/infrastructures/infid/radl":
                resp.status_code = 200
                resp.json.return_value = {"radl": "radltest"}
            elif url == "/infrastructures/infid/vms/vmid/contmsg":
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
    @patch("imclient.imclient.ServerProxy")
    def test_list(self, server_proxy, requests):
        """
        Test list operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureList.return_value = (True, ["inf1", "inf2"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.xmlrpc = "https://localhost:8899"
        options.restapi = None
        options.verify = False
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("list", options, [], parser)
        output = out.getvalue().strip()
        self.assertEquals(res, True)
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

        options.name = True
        proxy.GetInfrastructureRADL.side_effect = [(True, "description desc (name = 'some name')\nsystem s1 ()"),
                                                   (True, "description desc (name = 'some name2')\nsystem s2 ()")]

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("list", options, [], parser)
        output = out.getvalue().strip()
        self.assertEquals(res, True)
        self.assertIn("inf1    some name", output)
        self.assertIn("inf2    some name2", output)
        sys.stdout = oldstdout
        options.name = False

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("list", options, [".*hadoop.*"], parser)
        output = out.getvalue().strip()
        self.assertEquals(res, True)
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("list", options, [], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("list", options, [".*hadoop.*"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_create(self, server_proxy, requests):
        """
        Test create operation
        """
        proxy = MagicMock()
        proxy.CreateInfrastructure.return_value = (True, "inf1")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
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
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("create", options, [get_abs_path("../files/test.radl")], parser)
        self.assertIsNotNone(res)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully created with ID: inf1", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("create", options, [get_abs_path("../files/tosca.yml")], parser)
        self.assertIsNotNone(res)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully created with ID: inf1", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_removeresource(self, server_proxy, requests):
        """
        Test removeresource operation
        """
        proxy = MagicMock()
        proxy.RemoveResource.return_value = (True, ["1", "2"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.restapi = None
        options.quiet = False
        options.name = False
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("removeresource", options, ["infid", "1,2"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: ['1', '2'] successfully deleted.", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("removeresource", options, ["infid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully deleted.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_addresource(self, server_proxy, requests):
        """
        Test addresource operation
        """
        proxy = MagicMock()
        proxy.AddResource.return_value = (True, ["1"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("addresource", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully added.", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("addresource", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully added.", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("addresource", options, ["infid", get_abs_path("../files/tosca.yml")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: 1 successfully added.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_alter(self, server_proxy, requests):
        """
        Test alter operation
        """
        proxy = MagicMock()
        proxy.AlterVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("alter", options, ["infid", "vmid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully modified.", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("alter", options, ["infid", "vmid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully modified.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_reconfigure(self, server_proxy, requests):
        """
        Test reconfigure operation
        """
        proxy = MagicMock()
        proxy.Reconfigure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("reconfigure", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully reconfigured.", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("reconfigure", options, ["infid", get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully reconfigured.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getcontmsg(self, server_proxy, requests):
        """
        Test getcontmsg operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureContMsg.return_value = (True, "contmsg")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getcontmsg", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Msg Contextualizator: \n\ncontmsg", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getcontmsg", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Msg Contextualizator: \n\ncontmsg", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getstate(self, server_proxy, requests):
        """
        Test getstate operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureState.return_value = (True, {"state": "running", "vm_states": {"vm1": "running"}})
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getstate", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure is in state: running\nVM ID: vm1 is in state: running.", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getstate", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure is in state: running\nVM ID: vm1 is in state: running.", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getvminfo(self, server_proxy, requests):
        """
        Test getvminfo operation
        """
        proxy = MagicMock()
        proxy.GetVMInfo.return_value = (True, "radltest")
        proxy.GetVMProperty.return_value = (True, "property")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getvminfo", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getvminfo", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getinfo(self, server_proxy, requests):
        """
        Test getinfo operation
        """
        proxy = MagicMock()
        proxy.GetVMInfo.return_value = (True, "radltest")
        proxy.GetInfrastructureInfo.return_value = (True, ["vm1"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getinfo", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\nradltest", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getinfo", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\nradltest", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_destroy(self, server_proxy, requests):
        """
        Test destroy operation
        """
        proxy = MagicMock()
        proxy.DestroyInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("destroy", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)

        # Test using name instead of the ID
        options.name = True
        proxy.GetInfrastructureList.return_value = (True, ["inf1"])
        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("destroy", options, ["some name"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        self.assertEqual(proxy.GetInfrastructureList.call_args_list[0][0][1],
                         ".*description\s*.*\s*(\s*name\s*=\s*'some name'.*).*")
        self.assertEqual(proxy.DestroyInfrastructure.call_args_list[1][0][0], 'inf1')
        options.name = False

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("destroy", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

        out = StringIO()
        sys.stdout = out
        options.force = True
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("destroy", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_start(self, server_proxy, requests):
        """
        Test start operation
        """
        proxy = MagicMock()
        proxy.StartInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("start", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully started", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("start", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully started", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_stop(self, server_proxy, requests):
        """
        Test stop operation
        """
        proxy = MagicMock()
        proxy.StopInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("stop", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully stopped", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("stop", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully stopped", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getradl(self, server_proxy, requests):
        """
        Test getradl operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureRADL.return_value = (True, "radltest")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getradl", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getradl", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getvmcontmsg(self, server_proxy, requests):
        """
        Test getvmcontmsg operation
        """
        proxy = MagicMock()
        proxy.GetVMContMsg.return_value = (True, "getvmcontmsg")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getvmcontmsg", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("getvmcontmsg", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getvmcontmsg", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("getvmcontmsg", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_startvm(self, server_proxy, requests):
        """
        Test startvm operation
        """
        proxy = MagicMock()
        proxy.StartVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.quiet = False
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("startvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully started", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.quiet = False
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("startvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully started", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_stopvm(self, server_proxy, requests):
        """
        Test stopvm operation
        """
        proxy = MagicMock()
        proxy.StopVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("stopvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully stopped", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("stopvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully stopped", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_rebootvm(self, server_proxy, requests):
        """
        Test rebootvm operation
        """
        proxy = MagicMock()
        proxy.RebootVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("rebootvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully rebooted", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("rebootvm", options, ["infid", "vmid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("VM successfully rebooted", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getversion(self, server_proxy, requests):
        """
        Test getversion operation
        """
        proxy = MagicMock()
        proxy.GetVersion.return_value = (True, "1.0")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("getversion", options, [], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("1.0", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("getversion", options, [], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("1.0", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_export(self, server_proxy, requests):
        """
        Test export operation
        """
        proxy = MagicMock()
        proxy.ExportInfrastructure.return_value = (True, "strinf")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("export", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("strinf", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("export", options, ["infid"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("strinf", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_import(self, server_proxy, requests):
        """
        Test import operation
        """
        proxy = MagicMock()
        proxy.ImportInfrastructure.return_value = (True, "newinfid")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("import", options, [get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("New Inf: newinfid", output)

        out = StringIO()
        sys.stdout = out
        options.xmlrpc = None
        options.restapi = "https://localhost:8800"
        requests.side_effect = self.get_response
        res = main("import", options, [get_abs_path("../files/test.radl")], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("New Inf: newinfid", output)
        sys.stdout = oldstdout

    @patch("imclient.imclient.ServerProxy")
    def test_sshvm(self, server_proxy):
        """
        Test sshvm operation
        """
        proxy = MagicMock()

        radl = open(get_abs_path("../files/test.radl"), 'r').read()
        proxy.GetVMInfo.return_value = (True, radl)
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

        sys.stdout = out
        sys.stderr = out
        res = main("ssh", options, ["infid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 1022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

        # test proxy host
        radl = open(get_abs_path("../files/test_proxy.radl"), 'r').read()
        proxy.GetVMInfo.return_value = (True, radl)

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("sshpass -pyoyoyo ssh -p 22 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                      "ubuntu@10.0.0.1 -o ProxyCommand=sshpass -p passwd ssh -W %h:%p -p 22"
                      " -o StrictHostKeyChecking=no username@someserver.com", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    @patch("imclient.imclient.ServerProxy")
    def test_sshvm_key(self, server_proxy):
        """
        Test sshvm operation
        """
        proxy = MagicMock()

        radl = open(get_abs_path("../files/test_priv.radl"), 'r').read()
        proxy.GetVMInfo.return_value = (True, radl)
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("ssh -p 1022 -i /tmp/", output)
        self.assertIn(" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@10.0.0.1", output)
        sys.stdout = oldstdout
        sys.stderr = oldstderr

    @patch("imclient.imclient.ServerProxy")
    def test_sshvm_via_master(self, server_proxy):
        """
        Test sshvm operation via master VM
        """
        proxy = MagicMock()

        radl_master = open(get_abs_path("../files/test_ssh_master.radl"), 'r').read()
        radl_wn = open(get_abs_path("../files/test_ssh_wn.radl"), 'r').read()
        proxy.GetVMInfo.side_effect = [(True, radl_wn), (True, radl_master)]
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        oldstderr = sys.stderr
        sys.stdout = out
        sys.stderr = out
        res = main("sshvm", options, ["infid", "vmid", "1"], parser)
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn("ssh -p 22 -i /tmp/", output)
        self.assertIn(" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@10.0.0.2"
                      " -o ProxyCommand=ssh -W %h:%p -i /var/tmp/ubuntu_ubuntu_10.0.0.2.pem -p 22"
                      " -o StrictHostKeyChecking=no ubuntu@8.8.8.8", output)
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
    @patch("imclient.imclient.ServerProxy")
    def test_getoutputs(self, server_proxy, requests):
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
        self.assertEquals(res, True)
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
        self.assertIn("[-u|--xmlrpc-url <url>] [-r|--restapi-url <url>] [-v|--verify-ssl] "
                      "[-a|--auth_file <filename>] operation op_parameters", output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getcloudimages(self, server_proxy, requests):
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
        self.assertEquals(res, True)
        output = out.getvalue().strip()
        self.assertIn('"uri": "one://oneserver/1"', output)
        self.assertIn('"name": "image1"', output)
        self.assertIn('"uri": "one://oneserver:2"', output)
        self.assertIn('"name": "image2"', output)
        sys.stdout = oldstdout

    @patch('requests.request')
    @patch("imclient.imclient.ServerProxy")
    def test_getcloudusage(self, server_proxy, requests):
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
        self.assertEquals(res, True)
        output = json.loads(out.getvalue().strip())
        self.assertEqual({'cores': {'used': 5, 'limit': -1}}, output)
        sys.stdout = oldstdout

    @patch("imclient.imclient.ServerProxy")
    def test_wait(self, server_proxy):
        """
        Test wait operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureState.return_value = (True, {"state": "configured", "vm_states": {"vm1": "configured"}})
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        options.restapi = None
        options.quiet = False
        options.name = False
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        res = main("wait", options, ["infid"], parser)
        self.assertEquals(res, True)
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
        self.assertEquals(res, True)
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
        self.assertEquals(res, True)

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
