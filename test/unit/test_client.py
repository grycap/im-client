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
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

sys.path.append("..")
sys.path.append(".")

from im_client import main, get_parser
from mock import patch, MagicMock


def get_abs_path(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(tests_path, file_name)


class TestClient(unittest.TestCase):
    """
    Class to test the CtxtAgent
    """

    @patch("im_client.ServerProxy")
    def test_0list(self, server_proxy):
        """
        Test list operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureList.return_value = (True, ["inf1", "inf2"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("list", options, [], parser)
        output = out.getvalue().strip()
        self.assertIn("IDs: \n  inf1\n  inf2", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_create(self, server_proxy):
        """
        Test create operation
        """
        proxy = MagicMock()
        proxy.CreateInfrastructure.return_value = (True, "inf1")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("create", options, [get_abs_path("../files/test.radl")], parser)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully created with ID: inf1", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_removeresource(self, server_proxy):
        """
        Test removeresource operation
        """
        proxy = MagicMock()
        proxy.RemoveResource.return_value = (True, ["1", "2"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("removeresource", options, ["infid", "1,2"], parser)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: ['1', '2'] successfully deleted.", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_addresource(self, server_proxy):
        """
        Test addresource operation
        """
        proxy = MagicMock()
        proxy.AddResource.return_value = (True, ["1"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("addresource", options, ["infid", get_abs_path("../files/test.radl")], parser)
        output = out.getvalue().strip()
        self.assertIn("Resources with IDs: ['1'] successfully added.", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_alter(self, server_proxy):
        """
        Test alter operation
        """
        proxy = MagicMock()
        proxy.AlterVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("alter", options, ["infid", "vmid", get_abs_path("../files/test.radl")], parser)
        output = out.getvalue().strip()
        self.assertIn("VM successfully modified.", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_reconfigure(self, server_proxy):
        """
        Test reconfigure operation
        """
        proxy = MagicMock()
        proxy.Reconfigure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("reconfigure", options, ["infid", get_abs_path("../files/test.radl")], parser)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully reconfigured.", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getcontmsg(self, server_proxy):
        """
        Test getcontmsg operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureContMsg.return_value = (True, "contmsg")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getcontmsg", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("Msg Contextualizator: \n\ncontmsg", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getstate(self, server_proxy):
        """
        Test getstate operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureState.return_value = (True, {"state": "running", "vm_states": {"vm1": "running"}})
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getstate", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("The infrastructure is in state: running\nVM ID: vm1 is in state: running.", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getvminfo(self, server_proxy):
        """
        Test getvminfo operation
        """
        proxy = MagicMock()
        proxy.GetVMInfo.return_value = (True, "radltest")
        proxy.GetVMProperty.return_value = (True, "property")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getvminfo", options, ["infid", "vmid"], parser)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getinfo(self, server_proxy):
        """
        Test getinfo operation
        """
        proxy = MagicMock()
        proxy.GetVMInfo.return_value = (True, "radltest")
        proxy.GetInfrastructureInfo.return_value = (True, ["vm1"])
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getinfo", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("Info about VM with ID: vm1\nradltest", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_destroy(self, server_proxy):
        """
        Test destroy operation
        """
        proxy = MagicMock()
        proxy.DestroyInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("destroy", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully destroyed", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_start(self, server_proxy):
        """
        Test start operation
        """
        proxy = MagicMock()
        proxy.StartInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("start", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully started", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_stop(self, server_proxy):
        """
        Test stop operation
        """
        proxy = MagicMock()
        proxy.StopInfrastructure.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("stop", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("Infrastructure successfully stopped", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getradl(self, server_proxy):
        """
        Test getradl operation
        """
        proxy = MagicMock()
        proxy.GetInfrastructureRADL.return_value = (True, "radltest")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getradl", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("radltest", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getvmcontmsg(self, server_proxy):
        """
        Test getvmcontmsg operation
        """
        proxy = MagicMock()
        proxy.GetVMContMsg.return_value = (True, "getvmcontmsg")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getvmcontmsg", options, ["infid", "vmid"], parser)
        output = out.getvalue().strip()
        self.assertIn("getvmcontmsg", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_startvm(self, server_proxy):
        """
        Test startvm operation
        """
        proxy = MagicMock()
        proxy.StartVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("startvm", options, ["infid", "vmid"], parser)
        output = out.getvalue().strip()
        self.assertIn("VM successfully started", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_stopvm(self, server_proxy):
        """
        Test stopvm operation
        """
        proxy = MagicMock()
        proxy.StopVM.return_value = (True, "")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("stopvm", options, ["infid", "vmid"], parser)
        output = out.getvalue().strip()
        self.assertIn("VM successfully stopped", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_getversion(self, server_proxy):
        """
        Test getversion operation
        """
        proxy = MagicMock()
        proxy.GetVersion.return_value = (True, "1.0")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("getversion", options, [], parser)
        output = out.getvalue().strip()
        self.assertIn("1.0", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_export(self, server_proxy):
        """
        Test export operation
        """
        proxy = MagicMock()
        proxy.ExportInfrastructure.return_value = (True, "strinf")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("export", options, ["infid"], parser)
        output = out.getvalue().strip()
        self.assertIn("strinf", output)
        sys.stdout = oldstdout

    @patch("im_client.ServerProxy")
    def test_import(self, server_proxy):
        """
        Test import operation
        """
        proxy = MagicMock()
        proxy.ImportInfrastructure.return_value = (True, "newinfid")
        server_proxy.return_value = proxy
        options = MagicMock()
        options.auth_file = get_abs_path("../../auth.dat")
        parser = MagicMock()

        out = StringIO()
        oldstdout = sys.stdout
        sys.stdout = out
        main("import", options, [get_abs_path("../files/test.radl")], parser)
        output = out.getvalue().strip()
        self.assertIn("New Inf: newinfid", output)
        sys.stdout = oldstdout


if __name__ == '__main__':
    unittest.main()
