# IM - Infrastructure Manager client

[![PyPI](https://img.shields.io/pypi/v/im-client.svg)](https://pypi.org/project/im-client)
[![Tests](https://github.com/grycap/im-client/actions/workflows/main.yaml/badge.svg)](https://github.com/grycap/im-client/actions/workflows/main.yaml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/c74628a2fc134c2683d3fc57b571ce09)](https://www.codacy.com/gh/grycap/im-client/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=grycap/im-client&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/c74628a2fc134c2683d3fc57b571ce09)](https://www.codacy.com/app/micafer/im-client?utm_source=github.com&utm_medium=referral&utm_content=grycap/im-client&utm_campaign=Badge_Coverage)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://imdocs.readthedocs.io/en/latest/client.html)
[![SQAaaS badge](https://img.shields.io/badge/sqaaas%20software-gold-yellow)](https://eu.badgr.com/public/assertions/Zonx9GHHRiSxDVtabutm7g)

IM is a tool that ease the access and the usability of IaaS clouds by
automating the VMI selection, deployment, configuration, software installation,
monitoring and update of Virtual Appliances. It supports APIs from a large
number of virtual platforms, making user applications cloud-agnostic. In
addition it integrates a contextualization system to enable the installation
and configuration of all the user required applications providing the user with
a fully functional infrastructure.

```sh
Usage: im_client.py \
         [-u|--xmlrpc-url <url>] \
         [-r|--restapi-url <url>] \
         [-v|--verify-ssl] \
         [-a|--auth_file <filename>] \
         operation op_parameters
```

## Achievements

[![SQAaaS badge](https://github.com/EOSC-synergy/SQAaaS/raw/master/badges/badges_150x116/badge_software_gold.png)](https://eu.badgr.com/public/assertions/Zonx9GHHRiSxDVtabutm7g "SQAaaS gold badge achieved")

This software has received a gold badge according to the
[Software Quality Baseline criteria](https://github.com/indigo-dc/sqa-baseline)
defined by the [EOSC-Synergy](https://www.eosc-synergy.eu) project.

## 1 INSTALLATION

### 1.1 REQUISITES

IM is based on python, so Python 3 or higher runtime and standard
library must be installed in the system.

It is also required the [RADL parser](https://github.com/grycap/radl),
available in pip as the 'RADL' package. It is also required the Python
[Requests library](http://docs.python-requests.org/)
available as 'python-requests' in O.S. packages or 'requests' in pip.

### 1.2 OPTIONAL PACKAGES

In case of using the SSL secured version of the XMLRPC API the
[SpringPython framework](http://springpython.webfactional.com/) 
must be installed.

### 1.3 INSTALLING

#### 1.3.1 FROM PIP

You only have to call the install command of the pip tool with the IM-client
package.

```sh
pip install IM-client
```

#### 1.3.2 FROM SOURCE

You only need to install the tar-gziped file to any directoy:

```sh
tar xvzf IM-client-X.XX.tar.gz
```

#### 1.3.3 IM-Client Docker image

The IM Client has an official Docker container image available in Github
Container Registry that can be used instead of installing the CLI. You can
download it by typing:

```sh
sudo docker pull ghcr.io/grycap/im-client
```

You can exploit all the potential of the IM Client as if you download the CLI
and run it on your computer:

```sh
docker run --rm -ti -v "$PWD:/tmp/im" ghcr.io/grycap/im-client \
      -r https://server.com:8800 -a /tmp/im/auth.dat list
docker run --rm -ti -v "$PWD:/tmp/im" ghcr.io/grycap/im-client \
      -r https://server.com:8800 -a /tmp/im/auth.dat create /tmp/im/somefile.radl
```

### 1.4 CONFIGURATION

To avoid typing the parameters in all the client calls. The user can define a
config file "im_client.cfg" in the current directory or a file ".im_client.cfg"
in their home directory. In the config file the user can specify the following
parameters:

```sh
[im_client]
# only set one of the urls
#xmlrpc_url=http://localhost:8899
restapi_url=http://localhost:8800
auth_file=auth.dat
xmlrpc_ssl_ca_certs=/tmp/pki/ca-chain.pem
```

#### 1.4.1 AUTH FILE

The authorization file stores in plain text the credentials to access the
cloud providers, the IM service and the VMRC service. Each line of the file
is composed by pairs of key and value separated by semicolon, and refers to a
single credential. The key and value should be separated by " = ", that is
**an equals sign preceded and followed by one white space at least**, like
this:

```sh
id = id_value ; type = zzzz ; username = xxxx ; password = yyyy
```

Remember that the **InfrastructureManager auth line is mandatory**, like this:

```sh
id = im ; type = InfrastructureManager ; username = xxxx ; password = yyyy
```

or using an OIDC token:

```sh
id = im ; type = InfrastructureManager ; token = xxxxxx
```

Values can contain "=", and "\\n" is replaced by carriage return. The available
keys are:

* ``type`` indicates the service that refers the credential. The services
  supported are ``InfrastructureManager``, ``VMRC``, ``OpenNebula``, ``EC2``
  , ``FogBow``, ``OpenStack``, ``OCCI``, ``LibCloud``, ``Docker``, ``GCE``,
  ``Azure``, ``AzureClassic`` and ``Kubernetes``.

* ``username`` indicates the user name associated to the credential. In EC2
  it refers to the *Access Key ID*. In GCE it refers to *Service Account's
  Email Address*.

* ``password`` indicates the password associated to the credential. In EC2
  it refers to the *Secret Access Key*. In GCE it refers to *Service  Private
  Key* (either in JSON or PKCS12 formats). See how to get it and how to extract
  the private key file from
  [here](https://cloud.google.com/storage/docs/authentication#service_accounts).
  In OpenStack sites using 3.x_oidc_access_token authentication it indicates
  the OIDC access token.

* ``tenant`` indicates the tenant associated to the credential.
  This field is only used in the OpenStack plugin.

* ``host`` indicates the address of the access point to the cloud provider.
  This field is not used in IM, GCE, Azure, and EC2 credentials.

* ``proxy`` indicates the content of the proxy file associated to the
  credential. To refer to a file you must use the function
  "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is used in the OCCI and OpenStack plugins.

* ``project`` indicates the project name associated to the credential.
  This field is only used in the GCE plugin.

* ``public_key`` indicates the content of the public key file associated to
  the credential. To refer to a file you must use the function "file(cert.pem)"
  as shown in the example. This field is used in the Azure Classic and Docker
  plugins. For Azure Classic see how to get it
  [here](https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx).

* ``private_key`` indicates the content of the private key file associated to
  the credential. To refer to a file you must use the function "file(key.pem)"
  as shown in the example. This field is used in the Azure Classic and Docker
  plugins. For Azure Classic see how to get it
  [here](https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx).

* ``id`` associates an identifier to the credential. The identifier should be
  used as the label in the *deploy* section in the RADL.

* ``subscription_id`` indicates the subscription_id name associated to the
  credential. This field is only used in the Azure and Azure Classic plugins.
  To create a user to use the Azure (ARM) plugin check the documentation of
  the Azure python SDK:
  [here](https://azure-sdk-for-python.readthedocs.io/en/latest/quickstart_authentication.html#using-ad-user-password)

* ``token`` indicates the OpenID token associated to the credential. This
  field is used in the OCCI and also to authenticate with the
  InfrastructureManager. To refer to the output of a command you must
  use the function "command(command)" as shown in the examples.

##### OpenStack addicional fields

OpenStack has a set of addicional fields to access a cloud site:

* ``auth_version`` the auth version used to connect with the Keystone server.
  The possible values are: ``2.0_password`` or ``3.X_password``. The default
  value is ``2.0_password``.

* ``base_url`` base URL to the OpenStack API endpoint. By default, the
  connector obtains API endpoint URL from the server catalog, but if this
  argument is provided, this step is skipped and the provided value is used
  directly. The value is: `http://cloud_server.com:8774/v2/<tenant_id>`.
  
* ``service_region`` the region of the cloud site (case sensitive). It is used
  to obtain  the API endpoint URL. The default value is: ``RegionOne``.

* ``service_name`` the service name used to obtain the API endpoint URL.
  The default value is: ``Compute``.

* ``auth_token`` token which is used for authentication. If this argument is
  provided, normal authentication flow is skipped and the OpenStack API
  endpoint is directly hit with the provided token. Normal authentication
  flow involves hitting the auth service (Keystone) with the provided username
  and password and requesting an authentication token.

An example of the auth file:

<!-- markdownlint-disable MD013 -->
```sh
# OpenNebula site
id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
# OpenStack site using standard user, password, tenant format
id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant
# OpenStack site using VOMS proxy authentication
id = ostvoms; type = OpenStack; proxy = file(/tmp/proxy.pem); host = https://keystone:5000; tenant = tname
# OpenStack site using OIDC authentication for EGI Sites
id = ost; type = OpenStack; host = https://ostserver:5000; username = egi.eu; tenant = openid; password = command(oidc-token OIDC_ACCOUNT); auth_version = 3.x_oidc_access_token; domain = project_name_or_id
# IM auth data
id = im; type = InfrastructureManager; username = user; password = pass
# VMRC auth data
id = vmrc; type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
# EC2 auth data
id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
# Google compute auth data
id = gce; type = GCE; username = username.apps.googleusercontent.com; password = pass; project = projectname
# Docker site with certificates
id = docker; type = Docker; host = http://host:2375; public_key = file(/tmp/cert.pem); private_key = file(/tmp/key.pem)
# Docker site without SSL security
id = docker; type = Docker; host = http://host:2375
# OCCI VOMS site auth data
id = occi; type = OCCI; proxy = file(/tmp/proxy.pem); host = https://server.com:11443
# OCCI OIDC site auth data
id = occi; type = OCCI; token = token; host = https://server.com:11443
# Azure (RM) site auth data
id = azure; type = Azure; subscription_id = subscription-id; username = user@domain.com; password = pass
# Kubernetes site auth data
id = kub; type = Kubernetes; host = http://server:8080; username = user; password = pass
# FogBow auth data
id = fog; type = FogBow; host = http://server:8182; proxy = file(/tmp/proxy.pem)
# Azure Classic auth data
id = azurecla; type = AzureClassic; subscription_id = subscription_id; public_key = file(/tmp/cert.pem); private_key = file(/tmp/key.pem)
```
<!-- markdownlint-enable MD013 -->

### 1.4 INVOCATION

The program`im_client` is called like this:

```sh
Usage: im_client.py \
         [-u|--xmlrpc-url <url>] \
         [-r|--restapi-url <url>] \
         [-v|--verify-ssl] \
         [-a|--auth_file <filename>] \
         operation op_parameters
```

* option: -u|--xmlrpc-url url

   URL to the XML-RPC service.
   This option or the `-r` one must be specified.

* option:: -r|--rest-url url

   URL to the REST API on the IM service.
   This option or the `-u` one must be specified.

* option:: -v|--verify-ssl

   Verify the certificates of the SSL connection.
   The default value is `False`,

* option: -a|--auth_file filename

   Path to the authorization file, see [here](https://imdocs.readthedocs.io/en/latest/client.html#authorization-file).
   This option is compulsory.

* option: -f|--force

   Force the deletion of the infrastructure. Only for destroy operation.
   The default value is `False`.

* option: -q|--quiet

   Work in quiet mode. Avoid all unnecessary prints.
   The default value is `False`.

* option: -n|--name

   Show/use Infrastructure name in the selected operation.
   In case of list operation it will show the name of each infrastructure
   (if available). In other operations if this flag is set the user should
   specify the name of the infrastructure instead of the ID.
   The default value is `False`.

* operation:

   ``list [filter]``:
      List the infrastructure IDs created by the user. The ``filter`` parameter
      is optional and is a regex that will be used to filter the list of
      infrastructures.

   ``create <radlfile> [async_flag]``
      Create an infrastructure using RADL specified in the file with path
      ``radlfile``. The ``async_flag`` parameter is optional
      and is a flag to specify if the creation call will wait the resources
      to be created or return immediately the id of the infrastructure.

   ``destroy <infId>``
      Destroy the infrastructure with ID ``infId``.

   ``getinfo <infId>``
      Show the information about all the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``getcontmsg <infId>``
      Show the contextualization message of the infrastructure with ID
      ``infId``.

   ``getstate <infId>``
      Show the state of the infrastructure with ID ``infId``.

   ``getoutputs <infId>``
      Show the outputs of infrastructure with ID ``infId``
      (Only in case of TOSCA docs with REST API).

   ``getvminfo <infId> <vmId>``
      Show the information associated to the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``infId``.

   ``getvmcontmsg <infId> <vmId>``
      Show the contextualization message of the virtual machine with ID
      ``vmId`` associated to the infrastructure with ID ``infId``.

   ``addresource <infId> <radlfile> [ctxt_flag]``
      Add to infrastructure with ID ``infId`` the resources specifies in the
      RADL file with path ``radlfile``. The ``ctxt_flag`` parameter is optional
      and is a flag to specify if the contextualization step will be launched
      just after the VM addition. If not specified the contextualization step
      will be launched.

   ``removeresource <infId> <vmId> [ctxt_flag]``
      Destroy the virtual machine with ID ``vmId`` in the infrastructure with
      ID ``infId``. The ``ctxt_flag`` parameter is optional
      and is a flag to specify if the contextualization step will be launched
      just after the VM addition. If not specified the contextualization step
      will be launched.

   ``start <infId>``
      Resume all the virtual machines associated to the infrastructure with ID
      ``infId``, stopped previously by the operation ``stop``.

   ``stop <infId>``
      Stop (but not remove) the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``alter <infId> <vmId> <radlfile>``
      Modify the specification of the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``vmId``, using the RADL
      specification in file with path ``radlfile``.

   ``reconfigure <infId> [radl_file] [vm_list]``
      Reconfigure the infrastructure with ID ``infId`` and also update the
      configuration data. The last  ``vm_list`` parameter is optional
      and is a list integers specifying the IDs of the VMs to reconfigure.
      If not specified all the VMs will be reconfigured.

   ``startvm <infId> <vmId>``
      Resume the specified virtual machine ``vmId`` associated to the
      infrastructure with ID ``infId``, stopped previously by the operation
      ``stop``.

   ``stopvm <infId> <vmId>``
      Stop (but not remove) the specified virtual machine ``vmId`` associated
      to the infrastructure with ID infrastructure with ID ``infId``.

   ``rebootvm <infId> <vmId>``
      Reboot the specified virtual machine ``vmId`` associated to the
      infrastructure with ID ``infId``.

   ``sshvm <infId> <vmId> [show_only] [command]``
      Connect with SSH with the specified virtual machine ``vmId`` associated to
      infrastructure with ID ``infId``. In case that the specified VM does not
      have public IP the client will try to connect using the virtual machine
      with ID ``0`` as SSH proxy. The ``show_only`` parameter is optional
      and is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``command`` parameter is optional and enables
      the execution of a particular command in the VM.

   ``ssh <infId> [show_only] [command]``
      Connect with SSH with the virtual machine with ID ``0`` associated to
      infrastructure with ID ``infId``.
      The ``show_only`` parameter is optional
      and is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``command`` parameter is optional and enables
      the execution of a particular command in the VM.

   ``get <infId> <show_only> <src> <dst>``
      Copy with SCP from the virtual machine with ID ``0`` associated to
      infrastructure with ID ``infId``. The ``show_only`` parameter
      is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``scr`` parameneter is the path of the file
      in the remote VM, ``dst`` is the path on the local machine.

   ``getvm <infId> <vmId> <show_only> <src> <dst>``
      Copy with SCP from the specified virtual machine ``vmId`` associated to
      infrastructure with ID ``infId``. In case that the specified VM does not
      have public IP the client will try to connect using the virtual machine
      with ID ``0`` as SSH proxy. The ``show_only`` parameter
      is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``scr`` parameneter is the path of the file
      in the remote VM, ``dst`` is the path on the local machine.

   ``put <infId> <show_only> <src> <dst>``
      Copy with SCP to the virtual machine with ID ``0`` associated to
      infrastructure with ID ``infId``. The ``show_only`` parameter
      is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``scr`` parameneter is the path of the file
      in the local file, ``dst`` is the path on the remote VM.

   ``putvm <infId> <vmId> <show_only> <src> <dst>``
      Copy with SCP to the specified virtual machine ``vmId`` associated to
      infrastructure with ID ``infId``. In case that the specified VM does not
      have public IP the client will try to connect using the virtual machine
      with ID ``0`` as SSH proxy. The ``show_only`` parameter
      is a flag to specify if ssh command will only be shown in stdout
      instead of executed. The ``scr`` parameneter is the path of the file
      in the local file, ``dst`` is the path on the remote VM.

   ``export <infId> [delete]``
      Export the data of the infrastructure with ID ``infId``. The ``delete``
      parameter is optional and is a flag to specify if the infrastructure
      will be deleted from the IM service (the VMs are not deleted).

   ``import <json_file>``
      Import the data of an infrastructure previously exported with the
      previous function. The ``json_file`` is a file with the data generated
      with the  ``export`` function.

   ``wait <infId> <maxTime>``
      Wait the infrastructure with ID ``infId`` to be be in a final state
      ("configured", "unconfigured" or "failed"). It has an optional parameter
      ``maxTime`` with the max time to wait. It returns 0 if the infrastructure
      ends with a "configured" state or 1 otherwise.

   ``create_wait_outputs <radlfile>``
      This operation is a combination of the create, wait and getoutputs
      functions. First it creates the infrastructure using the specified
      ``inputfile``, then waits for it to be configured, and finally gets the
      TOSCA outputs. In case of failure in then infrastructure creation step
      only the error message will be returned. The results will be returned to
      stdout in json format::

```json
         {"infid": "ID", "error": "Error message"}
```

   ``change_auth <infId> <newAuthFile> [overwrite]``
      This operation enables to change the owner of infrastructure with ID
      ``infId`` using the authentication data from file ``newAuthFile``.
      The ``overwrite`` parameter is optional and is a flag to specify if the
      authentication data will be overwrited or will be appended. The default
      value is 0.

### 1.5 PYTHON CLIENT

IMClient can also be used as a Python library to access IM (since version
1.7.0):

```py
   from imclient import IMClient

   auth = IMClient.read_auth_data("/path/auth.dat")
   client = IMClient.init_client("https://im.egi.eu/im", auth)
   inf_desc = """
      network public (outbound = 'yes')

      system node (
      cpu.count>=2 and
      memory.size>=4g and
      net_interface.0.connection = 'public' and
      disk.0.os.name='linux' and
      disk.0.image.url = 'appdb://SCAI/egi.ubuntu.20.04?vo.access.egi.eu'
      )

      configure wn (
      @begin
      ---
      - tasks:
         - debug: msg="Configured!"
      @end
      )

      deploy node 1
   """
   success, inf_id = client.create(inf_desc)
   ...
   success, err = client.destroy(inf_id)
```
