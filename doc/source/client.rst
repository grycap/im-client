IM Command-line Interface (CLI)
===============================

The :program:`im_client` is a CLI client that uses XML-RPC API of IM Server.

Prerequisites
-------------

The :program:`im_client` needs at least Python 2.4 to run. If the XML-RPC API
is secured with SSL certificates (see :confval:`XMLRCP_SSL`),
`Spring Python <http://springpython.webfactional.com/>`_ should be installed.
The Debian package is named ``python-springpython``.

Invocation
----------

The :program:`im_client` is called like this::

   $ im_client.py [-u|--xmlrpc-url url] [-a|--auth_file filename] operation op_parameters

.. program:: im_client

.. option:: -u|--xmlrpc-url url

   URL to the XML-RPC service.
   The default value is ``http://localhost:8888``.

   .. todo::

      Change the default value of the port to XMLRCP_PORT.

.. option:: -a|--auth_file filename

   Path to the authorization file, see :ref:`auth-file`.
   This option is compulsory.

.. option:: operation

   ``list``
      List the infrastructure IDs created by the user.

   ``create radlfile``
      Create an infrastructure using RADL specified in the file with path
      ``radlfile``.

   ``destroy infId``
      Destroy the infrastructure with ID ``infId``.

   ``getinfo infId``
      Show the information about all the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``getcontmsg infId``
      Show the contextualization message of the infrastructure with ID ``id``.

   ``getvminfo infId vmId``
      Show the information associated to the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``infId``.

   ``getvmcontmsg infId vmId``
      Show the contextualization message of the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``infId``.

   ``addresource infId radlfile``
      Add to infrastructure with ID ``infId`` the resources specifies in the
      RADL file with path ``radlfile``.

   ``removeresource infId vmId``
      Destroy the virtual machine with ID ``vmId`` in the infrastructure with
      ID ``infId``.

   ``start infId``
      Resume all the virtual machines associated to the infrastructure with ID
      ``infId``, stopped previously by the operation ``stop``.

   ``stop infId``
      Stop (but not remove) the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``alter infId vmId radlfile``
      Modify the specification of the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``vmId``, using the RADL
      specification in file with path ``radlfile``.

   ``reconfigure infId``
      Reconfigure the infrastructure with ID ``infId`` and also update the
      configuration data.

.. _auth-file:

Authorization File
------------------

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
  supported are ``InfrastructureManager``, ``VMRC``, ``OpenNebula``, ``EC2``,
  ``OpenStack``, ``OCCI``, ``LibCloud``, ``Docker``, ``GCE``, ``Azure`` and ``LibVirt``.

* ``username`` indicates the user name associated to the credential. In EC2 and
  OpenStack it refers to the *Access Key ID*. In Azure it refers to the user 
  Subscription ID. In GCE it refers to *Service Account’s Email Address*. 

* ``password`` indicates the password associated to the credential. In EC2 and
  OpenStack it refers to the *Secret Access Key*. In GCE it refers to *Service 
  Private Key* (`more info <https://developers.google.com/console/help/new/#serviceaccounts>`_).

* ``host`` indicates the address of the access point to the cloud provider.
  This field is not used in IM and EC2 credentials.
  
* ``proxy`` indicates the content of the proxy file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is only used in the OCCI plugin.
  
* ``project`` indicates the project name associated to the credential.
  This field is only used in the GCE plugin.
  
* ``public_key`` indicates the content of the public key file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``private_key`` indicates the content of the private key file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``id`` associates an identifier to the credential. The identifier should be
  used as the label in the *deploy* section in the RADL.

An example of the auth file::

   id = one; type = OpenNebula; host = osenserve:2633; username = user; password = pass
   type = InfrastructureManager; username = user; password = pass
   type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
   id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
   id = oshost; type = OpenStack; host = oshost:8773; username = ACCESS_KEY; key = SECRET_KEY
   id = gce; type = GCE; username = username.apps.googleusercontent.com; password = pass; project = projectname
   id = docker; type = Docker; host = http://host:2375
   id = occi; type = OCCI; proxy = file(/tmp/proxy.pem); host = https://fc-one.i3m.upv.es:11443
   id = azure; type = Azure; username = subscription-id; public_key = file(cert.pem); private_key = file(key.pem)
   

IM Server does not store the credentials used in the creation of
infrastructures. Then the user has to provide them in every call of
:program:`im_client`.
