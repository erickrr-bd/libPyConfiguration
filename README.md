# libPyConfiguration

Dynamic, memory-secure configuration management engine for applications that connect to Elasticsearch.

libPyConfiguration builds, through a terminal interface (TUI), the configuration file used to connect to an Elasticsearch cluster: master nodes, certificate verification and authentication (HTTP Authentication or API Key). Credentials are always stored encrypted and are never displayed.

**Version:** 1.3.0 - November 2026
**Author:** Erick Roberto Rodriguez Rodriguez ([erodriguez@tekium.mx](mailto:erodriguez@tekium.mx), [erickrr.tbd93@gmail.com](mailto:erickrr.tbd93@gmail.com))

---

## Features

- Interactive creation, modification and display of the configuration (YAML) with [pythondialog](https://pythondialog.sourceforge.io/).
- **Encrypted credentials:** AES-256-GCM with a key derived by PBKDF2-HMAC-SHA256 (600,000 iterations), through libPyUtils.
- **Context binding:** each secret is authenticated with its own context (`<context>:<field>`), so encrypted values can't be swapped between fields or applications.
- **Memory hygiene:** the passphrase and the plaintext are wiped from memory (`zeroize`) right after use.
- **Hidden input:** passwords and API Keys are typed in a password box, without default values.
- **HTTPS enforced:** authentication can only be enabled when every host uses HTTPS.
- **Safe CA handling:** the selected CA certificate can be copied to the application's folder, so the original file's owner and permissions are never changed.
- **Validation on load:** a configuration file edited by hand is validated (types, authentication method and encrypted values) before being used.
- Atomic writes, `600` permissions on the configuration file and masked display of sensitive data.

## Requirements

- Python 3.12 or later.
- `dialog` system package (Debian/Ubuntu: `apt install dialog`; RHEL/Fedora: `dnf install dialog`).
- Python libraries:

| Library | Version |
|---|---|
| [libPyUtils](https://github.com/erickrr-bd/libPyUtils) | >= 2.4.0 |
| [libPyDialog](https://github.com/erickrr-bd/libPyDialog) | >= 2.4.0 |
| [libPyLog](https://github.com/erickrr-bd/libPyLog) | >= 2.2.1 |

## Installation

With pip:

```bash
pip install git+https://github.com/erickrr-bd/libPyConfiguration.git
```

With Poetry:

```toml
[tool.poetry.dependencies]
libPyConfiguration = { git = "https://github.com/erickrr-bd/libPyConfiguration.git" }
```

## Usage

### Constructor

```python
from libPyConfiguration import libPyConfiguration

configuration = libPyConfiguration(
	backtitle = "MY-APP-TOOL v1.0",          # Text displayed in the background of the TUI.
	context = "my_app",                      # Encryption context. The service that decrypts must use the same value.
	certificate_dir = "/opt/My-App/certs",   # Optional: the CA is copied here (ca.pem). None = use the file in place.
	browse_dir = "/"                         # Initial folder of the certificate selection box.
)
```

> `context` defaults to `"telk_alert"`. Always pass your application's own value.

### Create the configuration

```python
from libPyDialog import DialogCancelled

KEY_FILE = "/opt/My-App/configuration/key"
CONFIGURATION_FILE = "/opt/My-App/configuration/my_app.yaml"
LOG_FILE = "/var/log/My-App/my-app-tool-log"

configuration = libPyConfiguration("MY-APP-TOOL v1.0", context = "my_app", certificate_dir = "/opt/My-App/configuration/certs")
try:
	configuration.define_es_host()
	configuration.define_verificate_certificate()
	configuration.define_use_authentication(KEY_FILE, owner = "my_app")
	configuration.create_file(configuration.convert_object_to_dict(), CONFIGURATION_FILE, LOG_FILE, "my_app", "my_app")
except DialogCancelled:
	pass	# The user pressed Cancel/ESC.
```

The `define_*` methods raise `DialogCancelled` when the user cancels a dialog: the caller decides what to do (usually, return to the menu).

### Modify and display the configuration

```python
configuration = libPyConfiguration("MY-APP-TOOL v1.0", context = "my_app", certificate_dir = "/opt/My-App/configuration/certs")
configuration.modify_configuration(CONFIGURATION_FILE, KEY_FILE, LOG_FILE, "my_app", "my_app")
configuration.display_configuration(CONFIGURATION_FILE, LOG_FILE, "my_app", "my_app")
```

`modify_configuration` only rewrites the file if something actually changed. Current credentials are never decrypted or displayed: to change one, a new value is typed.

### Read the configuration in a service

A daemon doesn't need the terminal interface. `convert_dict_to_object` validates the data and doesn't use `dialog`, so the object can be created without its constructor:

```python
from libPyUtils import libPyUtils

utils = libPyUtils()
configuration = libPyConfiguration.__new__(libPyConfiguration)
configuration.convert_dict_to_object(utils.read_yaml_file(CONFIGURATION_FILE))
```

To decrypt a credential, use the same context used to encrypt it (`<context>:<field>`):

```python
passphrase = utils.get_passphrase(KEY_FILE, owner = "my_app")
try:
	api_key_id = utils.decrypt_data(configuration.api_key_id, passphrase, context = "my_app:api_key_id")
	api_key = utils.decrypt_data(configuration.api_key, passphrase, context = "my_app:api_key")
finally:
	utils.zeroize(passphrase)
```

[libPyElk](https://github.com/erickrr-bd/libPyElk) does this for you: `libPyElk().create_connection(configuration, KEY_FILE, "my_app", owner = "my_app")`.

## Configuration file

```yaml
es_host:
- https://es1.example.com:9200
- https://es2.example.com:9200
verificate_certificate_ssl: true
certificate_file: /opt/My-App/configuration/certs/ca.pem
use_authentication: true
authentication_method: API Key
api_key_id:          # (ciphertext, nonce, auth_tag, salt)
- !!binary |
  ...
api_key:
- !!binary |
  ...
```

| Field | Type | Description |
|---|---|---|
| `es_host` | list | URLs of the master nodes (`http(s)://host:port`). |
| `verificate_certificate_ssl` | bool | `true` if a CA certificate is used to verify the cluster. |
| `certificate_file` | str | CA certificate (only if `verificate_certificate_ssl` is `true`). |
| `use_authentication` | bool | `true` if an authentication method is used. |
| `authentication_method` | str | `HTTP Authentication` or `API Key`. |
| `http_authentication_user`, `http_authentication_password` | encrypted | Only with `HTTP Authentication`. |
| `api_key_id`, `api_key` | encrypted | Only with `API Key`. |

## API

| Method | Description |
|---|---|
| `define_es_host()` | Asks for the master nodes (1-10, duplicates removed). |
| `define_verificate_certificate()` | Asks whether to verify the certificate with a CA (only with HTTPS hosts). |
| `define_use_authentication(key_file, owner = None)` | Asks for the authentication method and encrypts its credentials. |
| `convert_object_to_dict()` | Returns the configuration as a dictionary. |
| `convert_dict_to_object(data)` | Loads and validates a dictionary (raises `ValueError` if it is invalid). |
| `create_file(data, configuration_file, log_file_name, user, group)` | Creates the YAML file (`600`) and secures the copied CA. |
| `modify_configuration(configuration_file, key_file, log_file_name, user, group)` | Modifies hosts, certificate and/or authentication. |
| `modify_es_host(...)`, `modify_verificate_certificate(...)`, `modify_use_authentication(...)` | Modify one section (used by `modify_configuration`). |
| `display_configuration(configuration_file, log_file_name, user, group)` | Displays the file with the sensitive data masked. |

## Migrating from 1.2

Version 1.3.0 changes how credentials are encrypted (context binding). Configuration files created with 1.2 can't be decrypted with the new context:

1. Read them once with `decrypt_data(..., allow_legacy = True)` (or `libPyElk().create_connection(..., allow_legacy = True)`).
2. Save the credentials again with `modify_configuration` → *Authentication* → *Data*.
3. Remove `allow_legacy` afterwards: the old format doesn't bind each secret to its field.

Other changes:

- Canceling a dialog raises `DialogCancelled` (libPyDialog >= 2.4.0) instead of returning `None`.
- `define_use_authentication` accepts `owner` (expected owner of the key file).
- In the authentication menu, the option that switches to the other method is now called **Switch**.
- The selected CA is never `chown`ed in place: use `certificate_dir` to copy it.

## Changelog

### 1.3.0 - November 2026
- Credentials encrypted with context (`<context>:<field>`) and wiped from memory after use.
- Password boxes without default values for passwords and API Keys.
- HTTPS required to enable authentication.
- CA certificate copied to `certificate_dir`; the original file is never modified.
- Validation of the configuration file on load.
- Change detection by comparing data (the file is only rewritten if something changed).
- Fixed: log ownership overwritten by the HTTP username, removal of hosts logged even when not confirmed, compatibility with libPyUtils/libPyDialog 2.4.0.
