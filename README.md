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

1. INSTALLATION
===============

1.1 REQUISITES
--------------

IM is based on python, so Python 2.4 or higher runtime and standard library must
be installed in the system.

It is also required to install the Python Lex & Yacc library (http://www.dabeaz.com/ply/).
It is available in all of the main distributions as 'python-ply' package.

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

The authorization data is used to validate access to the components in the
infrastructure. This file is composed of a set of "key - value" pairs,
where the user specifies the authorization data for all the components and cloud
deployments available. File auth.dat shows examples of authorization data.

The list of "key" values that must be specified for each component are:

* id: An optional field used to identify the virtual deployment. It must be unique
      in the authorization data.
* type: The type of the component. It can be any of the components of the
        architecture, such as the "InfrastructureManager", "VMRC" or any of
        the cloud deployments currently supported by the IM: OpenNebula, EC2,
        OpenStack, OCCI, LibCloud, GCE or LibVirt.
* username: The name of the user for the authentication. In the EC2 and OpenStack
            cases it refers to the Access Key ID value. password: The password for
            the authentication. In the EC2 and OpenStack cases it refers to the
            Secret Access Key value. In the GCE case it can refer to the CLIENT_ID
            and CLIENT_SECRET (using Installed Application authentication) or
            the SERVICE_ACCOUNT_EMAIL and RSA_PRIVATE_KEY (using the Service 
            Account authentication)
* host: The address to the server in format "address:port" to specify the cloud
        deployment to access. In the EC2 or GCE and in the system components (IM and VMRC)
        this field is not used.

An example of the auth file:

```
id = one; type = OpenNebula; host = server:2633; username = user; password = pass
type = InfrastructureManager; username = user; password = pass
type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
id = ec2; type = EC2; username = ACESS_KEY; password = SECRET_KEY
id = gce; type = GCE; username = CLIENT_ID; password = CLIENT_SECRET; project = project-name
id = gce2; type = GCE; username = SERVICE_ACC_EMAIL; password = file(path_to_pem_file); project = project-name
id = docker; type = Docker; host = server:2375
id = occi; type = OCCI; host = server:8443; proxy = file(/tmp/proxy.pem)
id = libcloud; type = LibCloud; driver = EC2; username = ACESS_KEY; password = SECRET_KEY

```
         
### 1.4.2 SECURITY

Security is disabled by default, but it should be taken into account that it would
be possible that someone that has local network access can "sniff" the traffic and
get the messages with the IM with the authorisation data with the cloud providers.

I can be activated both in the XMLRPC and REST APIs. Setting this variables:

```
XMLRCP_SSL = True
```

And then set the variables: XMLRCP_SSL_CA_CERTS to your CA certificates paths.


