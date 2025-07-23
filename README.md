# libPyConfiguration v1.0

Easy management of configuration files for Python and ElasticSearch applications.

The project was born from the need for an easy-to-use library for managing configuration files (YAML files) for applications developed in Python that require a connection to ElasticSearch.

## Characteristics
- Connection data is stored in both a libPyConfiguration object and a YAML file.
- Requests the data needed to connect to ElasticSearch using a graphical interface (python-dialog).
- It's possible to define an authentication mechanism for connecting to ElasticSearch (HTTP Authentication or API Key).
- It's possible to define the use of the secure HTTPS protocol for the connection to ElasticSearch.
- It's possible to define SSL certificate verification for greater security.
- Allows you to modify the current configuration if necessary.
- Sensitive data such as user credentials are stored encrypted (AES-GCM).

# Requirements
- Red Hat 8 or Rocky Linux 8 (Tested on Rocky Linux 8.10)
- Python 3.12

**NOTE:** The versions displayed are the versions with which it was tested. This doesn't mean that versions older than these don't work.

# Installation

Copy the "libPyConfiguration" folder to the following path:

`/usr/local/lib/python3.12/site-packages/`

**NOTE:** The path depends on the version of Python being used.
