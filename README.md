# libPyConfiguration (v1.2)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Configuration Engine](https://img.shields.io/badge/engine-YAML%20Serialization-lightgrey.svg)](https://pyyaml.org/)
[![Security Hardening](https://img.shields.io/badge/security-Pentest--compliant-brightgreen.svg)](#)

**libPyConfiguration** is a dynamic, memory-secure configuration management engine written in Python. Specially designed for Terminal User Interfaces (TUI) and system automation environments, it abstracts the complexity of capturing, validating, modifying, and storing complex cluster topologies and database connection states.

It acts as a secure marshalling layer that interfaces with data encryption components to encrypt sensitive credentials at rest, enforces multi-layer input sanitization, and automatically provisions UNIX-level access control lists (ACLs) onto the generated configuration stores.

---

## ✨ Features

*   **Polymorphic Topology Mapping:** Dynamically provisions and handles changing states for cluster nodes, SSL/TLS validation tracks, HTTP Basic Authentication fields, and secure API Key scopes.
*   **Cryptographic Data-at-Rest Integration:** Seamlessly coordinates with low-level encryption bindings to capture user input, encrypt it via runtime-supplied passphrases, and securely serialize it into standard YAML outputs.
*   **Granular Multi-State CRUD Operations:** Complete structural state machine engine capable of parsing existing runtime models, editing discrete parameters, logging isolated delta adjustments, and safely tracking changes using cryptographic file verification hashes.
*   **Defense-in-Depth Telemetry:** Fully decoupled input sanitization checks parameters independently of the User Interface layer, protecting cluster profiles from empty fields, invalid inputs, or sudden terminal dropouts (`ESC`/Cancel).
*   **UNIX Hardening & System Seeding:** Enforces strict execution permission flags (`600` - read/write exclusively for the owner) and reassigns file descriptors to low-privilege service group mappings (`snap_tool`).

---

## 🛠️ Security Hardening (Pentest-Compliant)

Standard configuration modules often store backend credentials in text profiles or output them to standard terminal lines, exposing them to exploitation chains. 

**libPyConfiguration** systematically mitigates these vectors through the following runtime guards:
1.  **Shoulder-Surfing Remediation:** Prompts for critical API Secrets, authorization tokens, and admin passwords using visual text-masking boundaries, ensuring secrets are never echoed in clear text within active terminal panels.
2.  **Strict Safe Key Access:** Accesses structural dictionaries via defensive `.get()` parameters with strict default type objects, preventing data injection attempts or unhandled application crashes (`KeyError`) if fields are missing.
3.  **Encrypted Exports & Minimum ACLs:** Outputs serialized properties exclusively under rigorous access filters, restricting local access vectors by dropping standard read parameters for unprivileged local accounts.

---

## 📋 API Usage Reference

### Main Architecture Routines

| Method | Purpose |
| :--- | :--- |
| `define_es_host()` | Captures total node topologies via interactive integer fields and constructs matching cluster matrices. |
| `define_verificate_certificate()` | Triggers conditional TLS path validation pipelines if an active HTTPS endpoint context is detected. |
| `define_use_authentication(key_file)` | Intercepts, isolates, encrypts, and builds targeted credentials lists securely based on the chosen authentication path. |
| `convert_object_to_dict()` | Safely flattens the active instance variables into clean dictionary blocks ready for data serialization. |
| `convert_dict_to_object(data)` | Hydrates the object memory spaces, evaluating active topologies using safe default failovers to avoid internal key faults. |
| `modify_configuration(...)` | Maps internal modification targets, verifies runtime deltas using file hashes, and records isolated administrative adjustment statements. |

---

## 🚀 Quick Start Example

Here is how you can initialize, configure, and safely serialize a cluster configuration profile:

```python
from libPyConfiguration import libPyConfiguration

# Initialize the configuration controller with a background title for the TUI
config_manager = libPyConfiguration(backtitle="SNAP-TOOL v3.4.1 Configuration Portal")

# 1. Define Cluster Hosts dynamically (Opens interactive TUI forms)
config_manager.define_es_host()

# 2. Configure SSL/TLS Validation Tracks
config_manager.define_verificate_certificate()

# 3. Intercept and Encrypt Access Credentials
# Sensitive inputs will be masked on screen and encrypted in memory using the key file
config_manager.define_use_authentication(key_file="/etc/Snap-Tool/configuration/key")

# 4. Flatten and Safely Serialize Configuration to Disk
# Automatically applies 600 permissions and changes ownership to the snap_tool user
state_dict = config_manager.convert_object_to_dict()

config_manager.create_file(
    configuration_data=state_dict,
    configuration_file="/etc/Snap-Tool/configuration/es_conf.yaml",
    log_file_name="/var/log/Snap-Tool/snap-tool",
    user="snap_tool",
    group="snap_tool"
)
```
---

📄 File Security Output Verification
Once a configuration store is written to disk, you can verify that the library successfully locked down local file access permissions:

```bash
$ ls -l /etc/Snap-Tool/configuration/es_conf.yaml
-rw------- 1 snap_tool snap_tool 412 Jul 14 19:55 /etc/Snap-Tool/configuration/es_conf.yaml
```

(Notice the strict -rw------- [600] mask—any other local user attempting to access or parse this file will be completely rejected by the OS kernel).
