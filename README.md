IM - Infrastructure Manager client
==================================

IM is a tool that ease the access and the usability of IaaS clouds by automating
the VMI selection, deployment, configuration, software installation, monitoring
and update of Virtual Appliances. It supports APIs from a large number of
virtual platforms, making user applications cloud-agnostic. In addition it
integrates a contextualization system to enable the installation and
configuration of all the user required applications providing the user with a
fully functional infrastructure.

```
usage: client.py [-u|--xmlrpc-url <url>] [-a|--auth_file <filename>] operation op_parameters
```

1 INSTALLATION
===============

1.1 REQUISITES
--------------

IM is based on python, so Python 2.4 or higher runtime and standard library must
be installed in the system.

It is also required to install the RADL parser (https://github.com/grycap/radl), available in pip
as the 'RADL' package.

1.2 OPTIONAL PACKAGES
--------------

In case of using the SSL secured version of the XMLRPC API the SpringPython
framework (http://springpython.webfactional.com/) must be installed.

1.3 INSTALLING
--------------

### 1.3.1 FROM PIP

You only have to call the install command of the pip tool with the IM-client package.

```
pip install IM-client
```

### 1.3.2 FROM SOURCE

You only need to install the tar-gziped file to any directoy:

```
$ tar xvzf IM-client-X.XX.tar.gz
```

1.4 CONFIGURATION
--------------

To avoid typing the parameters in all the client calls. The user can define a config
file "im_client.cfg" in the current directory or a file ".im_client.cfg" in their 
home directory. In the config file the user can specify the following parameters:

```
[im_client]
xmlrpc_url=http://localhost:8899
auth_file=auth.dat
xmlrpc_ssl=no
xmlrpc_ssl_ca_certs=/tmp/pki/ca-chain.pem
```

* CLIENT_DIR - must be set to the full path where the IM client is installed 
            (e.g. /usr/local/im-client)
            
### 1.4.1 AUTH FILE

The authorization file stores in plain text the credentials to access the
cloud providers, the IM service and the VMRC service. Each line of the file
is composed by pairs of key and value separated by semicolon, and refers to a
single credential. The key and value should be separated by " = ", that is
**an equals sign preceded and followed by one white space at least**, like
this::

   id = id_value ; type = value_of_type ; username = value_of_username ; password = value_of_password 

Values can contain "=", and "\\n" is replaced by carriage return. The available
keys are:

* ``type`` indicates the service that refers the credential. The services
  supported are ``InfrastructureManager``, ``VMRC``, ``OpenNebula``, ``EC2``,, ``FogBow``, 
  ``OpenStack``, ``OCCI``, ``LibCloud``, ``Docker``, ``GCE``, ``Azure``, ``Kubernetes`` and ``LibVirt``.

* ``username`` indicates the user name associated to the credential. In EC2
  it refers to the *Access Key ID*. In Azure it refers to the user 
  Subscription ID. In GCE it refers to *Service Account’s Email Address*. 

* ``password`` indicates the password associated to the credential. In EC2
  it refers to the *Secret Access Key*. In GCE it refers to *Service 
  Private Key*. See how to get it and how to extract the private key file from
  `here info <https://cloud.google.com/storage/docs/authentication#service_accounts>`_).

* ``tenant`` indicates the tenant associated to the credential.
  This field is only used in the OpenStack plugin.

* ``host`` indicates the address of the access point to the cloud provider.
  This field is not used in IM and EC2 credentials.
  
* ``proxy`` indicates the content of the proxy file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is only used in the OCCI plugin.
  
* ``project`` indicates the project name associated to the credential.
  This field is only used in the GCE plugin.
  
* ``public_key`` indicates the content of the public key file associated to the credential.
  To refer to a file you must use the function "file(cert.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``private_key`` indicates the content of the private key file associated to the credential.
  To refer to a file you must use the function "file(key.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``id`` associates an identifier to the credential. The identifier should be
  used as the label in the *deploy* section in the RADL.

#### OpenStack addicional fields

OpenStack has a set of addicional fields to access a cloud site:

* ``auth_version`` the auth version used to connect with the Keystone server.
  The possible values are: ``2.0_password`` or ``3.X_password``. The default value is ``2.0_password``.

* ``base_url`` base URL to the OpenStack API endpoint. By default, the connector obtains API endpoint URL from the 
  server catalog, but if this argument is provided, this step is skipped and the provided value is used directly.
  The value is: http://cloud_server.com:8774/v2/<tenant_id>.
  
* ``service_region`` the region of the cloud site (case sensitive). It is used to obtain  the API 
  endpoint URL. The default value is: ``RegionOne``.

* ``service_name`` the service name used to obtain the API endpoint URL. The default value is: ``Compute``.

* ``auth_token`` token which is used for authentication. If this argument is provided, normal authentication 
  flow is skipped and the OpenStack API endpoint is directly hit with the provided token. Normal authentication 
  flow involves hitting the auth service (Keystone) with the provided username and password and requesting an
  authentication token.

An example of the auth file:

```
id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant
id = im; type = InfrastructureManager; username = user; password = pass
id = vmrc; type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
id = gce; type = GCE; username = username.apps.googleusercontent.com; password = pass; project = projectname
id = docker; type = Docker; host = http://host:2375
id = occi; type = OCCI; proxy = file(/tmp/proxy.pem); host = https://fc-one.i3m.upv.es:11443
id = azure; type = Azure; username = subscription-id; public_key = file(cert.pem); private_key = file(key.pem)
id = kub; type = Kubernetes; host = http://server:8080; username = user; password = pass
```
