"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyConfiguration
libPyConfiguration v1.3.0 - November 2026
Dynamic, memory-secure configuration management engine written in Python.
Requires libPyUtils >= 2.4.0, libPyDialog >= 2.4.0 and libPyLog >= 2.2.1.
"""
from os import path
from copy import deepcopy
from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog, DialogCancelled

HTTP_AUTH = "HTTP Authentication"
API_KEY = "API Key"
AUTH_METHOD_NAMES = (HTTP_AUTH, API_KEY)

# Maximum number of master nodes accepted in a single form.
MAX_MASTER_NODES = 10

# Accepted CA certificate extensions and name of the copy stored in certificate_dir.
CERTIFICATE_EXTENSIONS = (".pem", ".crt")
CERTIFICATE_NAME = "ca.pem"

# Encrypted credentials: tag -> (attribute, prompt, hidden input, label).
CREDENTIAL_FIELDS = {
	"Username": ("http_authentication_user", "Enter username:", False, "Username"),
	"Password": ("http_authentication_password", "Enter the password:", True, "Password"),
	"ID": ("api_key_id", "Enter the API Key ID:", False, "API Key ID"),
	"API Key": ("api_key", "Enter the API Key:", True, "API Key")
}
METHOD_FIELDS = {HTTP_AUTH: ("Username", "Password"), API_KEY: ("ID", "API Key")}

# Dialog choices (created once at import time).
CONFIGURATION_FIELDS = (("Host", "ElasticSearch Host", 0), ("Certificate SSL", "Enable or disable certificate verification", 0), ("Authentication", "Enable or disable authentication method", 0))
AUTHENTICATION_METHOD_OPTIONS = ((HTTP_AUTH, "Use HTTP Authentication", 0), (API_KEY, "Use API Key", 0))
ES_HOST_OPTIONS = (("1", "Add New Hosts"), ("2", "Modify Hosts"), ("3", "Remove Hosts"))
OPTIONS_VERIFICATE_CERTIFICATE_TRUE = (("Disable", "Disable certificate verification", 0), ("Certificate File", "Change certificate file", 0))
OPTIONS_VERIFICATE_CERTIFICATE_FALSE = (("Enable", "Enable certificate verification", 0),)
OPTIONS_AUTHENTICATION_TRUE = (("Disable", "Disable authentication method", 0), ("Method", "Modify authentication method", 0))
OPTIONS_AUTHENTICATION_FALSE = (("Enable", "Enable authentication", 0),)
OPTIONS_AUTHENTICATION_MODIFY = (("Switch", "Switch to the other authentication method", 0), ("Data", "Modify authentication method data", 0))
OPTIONS_HTTP_AUTHENTICATION = (("Username", "Username for HTTP Authentication", 0), ("Password", "User password", 0))
OPTIONS_API_KEY = (("ID", "API Key ID", 0), ("API Key", "API Key", 0))


class libPyConfiguration:

	def __init__(self, backtitle: str = "", context: str = "telk_alert", certificate_dir: str | None = None, browse_dir: str = "/") -> None:
		"""
		Class constructor.

		Parameters:
			backtitle (str): Text displayed in the background.
			context (str): Prefix that binds the encrypted secrets to this application (authenticated by AES-GCM).
			               The service that decrypts them must use the same value.
			certificate_dir (str | None): If set, the selected CA certificate is copied into this directory and only
			                              the copy gets its owner/permissions changed. If None, the selected file is
			                              referenced in place and its owner/permissions are never changed.
			browse_dir (str): Initial directory of the certificate selection box.
		"""
		self.es_host = []
		self.api_key = ()
		self.api_key_id = ()
		self.context = context
		self.browse_dir = browse_dir
		self.certificate_dir = certificate_dir
		self.logger = libPyLog()
		self.utils = libPyUtils()
		self.certificate_file = None
		self.use_authentication = False
		self.authentication_method = None
		self.http_authentication_user = ()
		self.http_authentication_password = ()
		self.dialog = libPyDialog(backtitle)
		self.verificate_certificate_ssl = False


	# --- Internal helpers ----------------------------------------------------------------------
	def _log(self, message, level: int, tag: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that writes an entry in the log file.
		"""
		self.logger.create_log(message, level, tag, use_file_handler = True, file_name = log_file_name, user = user, group = group)


	@staticmethod
	def _unique(hosts: list) -> list:
		"""
		Method that removes duplicated hosts keeping their order.
		"""
		return list(dict.fromkeys(hosts))


	def _ask_new_hosts(self, title: str) -> list:
		"""
		Method that asks for the total of master nodes (with limits) and their URLs.
		"""
		total = self.dialog.create_integer_inputbox(f"Enter the total number of master nodes (1-{MAX_MASTER_NODES}):", 8, 50, "1", min_value = 1, max_value = MAX_MASTER_NODES)
		tuple_to_form = self.utils.generate_tuple_to_form(total, "ES Host")
		return self._unique(self.dialog.create_url_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, title))


	def _https_required(self) -> bool:
		"""
		Method that verifies that all the hosts use HTTPS (required to send credentials).
		"""
		if self.utils.validate_https_urls(self.es_host):
			return True
		self.dialog.create_message("\nAuthentication requires all ElasticSearch hosts to use HTTPS.", 8, 50, "Error Message")
		return False


	def _select_certificate(self) -> str:
		"""
		Method that asks for the CA certificate. If certificate_dir is set, the file is copied there.

		Returns:
			certificate_file (str): Path of the certificate that will be used.
		"""
		start = path.dirname(self.certificate_file) + "/" if self.certificate_file else self.browse_dir
		selected = self.dialog.select_file(start, 15, 70, "Select the CA certificate:", list(CERTIFICATE_EXTENSIONS))
		if self.certificate_dir is None:
			return selected
		self.utils.create_folder(self.certificate_dir)
		destination = path.join(self.certificate_dir, CERTIFICATE_NAME)
		if path.realpath(selected) != path.realpath(destination):
			self.utils.copy_file(selected, destination)
		return destination


	def _secure_certificate(self, certificate_file: str | None, user: str = None, group: str = None) -> None:
		"""
		Method that applies owner/permissions to the certificate copy (never to a file outside certificate_dir).
		"""
		if not certificate_file or self.certificate_dir is None:
			return
		certificate_dir = path.realpath(self.certificate_dir)
		certificate = path.realpath(certificate_file)
		if path.dirname(certificate) != certificate_dir:
			return
		self.utils.change_owner(certificate_dir, user, group, "700")
		self.utils.change_owner(certificate, user, group, "600")


	def _with_passphrase(self, key_file: str, owner: str, action):
		"""
		Method that reads the passphrase once, runs the action and always wipes it from memory.
		"""
		passphrase = self.utils.get_passphrase(key_file, owner = owner)
		try:
			return action(passphrase)
		finally:
			self.utils.zeroize(passphrase)


	def _encrypt_secret(self, passphrase: bytearray, tag: str) -> tuple:
		"""
		Method that asks for a credential (hidden input for secrets, no default value) and returns it encrypted.
		"""
		field, prompt, hidden, label = CREDENTIAL_FIELDS[tag]
		if hidden:
			value = self.dialog.create_passwordbox(prompt, 9, 60, True, title = label)
		else:
			value = self.dialog.create_inputbox(prompt, 8, 50, "")
		buffer = bytearray(value.encode("utf-8"))
		try:
			return self.utils.encrypt_data(buffer, passphrase, context = f"{self.context}:{field}")
		finally:
			self.utils.zeroize(buffer)


	def _clear_credentials(self) -> None:
		"""
		Method that removes all the stored credentials.
		"""
		self.http_authentication_user = ()
		self.http_authentication_password = ()
		self.api_key_id = ()
		self.api_key = ()


	def _ask_credentials(self, method: str, passphrase: bytearray) -> None:
		"""
		Method that asks for all the credentials of an authentication method.
		The object is only updated once every value was entered.
		"""
		values = {CREDENTIAL_FIELDS[tag][0]: self._encrypt_secret(passphrase, tag) for tag in METHOD_FIELDS[method]}
		self._clear_credentials()
		for field, value in values.items():
			setattr(self, field, value)
		self.authentication_method = method


	@staticmethod
	def _encrypted_field(configuration_data: dict, field: str):
		"""
		Method that validates an encrypted value read from the YAML file (ciphertext, nonce, auth_tag, salt).
		"""
		value = configuration_data.get(field)
		if not isinstance(value, (list, tuple)) or len(value) != 4 or not all(isinstance(item, bytes) for item in value):
			raise ValueError(f"Invalid {field} in the configuration file.")
		return value


	# --- Definition ----------------------------------------------------------------------------
	def define_es_host(self) -> None:
		"""
		Method that defines the master nodes of the cluster.
		"""
		self.es_host = self._ask_new_hosts("ElasticSearch Hosts")


	def define_verificate_certificate(self) -> None:
		"""
		Method that defines whether the SSL certificate needs to be verified or not.
		"""
		if not self.utils.validate_https_urls(self.es_host):
			return
		if self.dialog.create_yes_or_no("\nIs SSL certificate verification required?\n\n**Note: Available only when using HTTPS.", 9, 50, "Certificate SSL Verification"):
			self.certificate_file = self._select_certificate()
			self.verificate_certificate_ssl = True


	def define_use_authentication(self, key_file: str, owner: str = None) -> None:
		"""
		Method that defines whether an authentication method is required or not.

		Parameters:
			key_file (str): Key file path.
			owner (str): User expected to own the key file.
		"""
		if not self.dialog.create_yes_or_no("\nIs an authentication method (HTTP Authentication or API Key) required?", 8, 50, "Authentication Method"):
			return
		if not self._https_required():
			return
		method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
		self._with_passphrase(key_file, owner, lambda passphrase: self._ask_credentials(method, passphrase))
		self.use_authentication = True


	# --- Conversion ----------------------------------------------------------------------------
	def convert_object_to_dict(self) -> dict:
		"""
		Method that converts an object of type libPyConfiguration into a dictionary.

		Returns:
			configuration_data_json (dict): Dictionary with the object's data.
		"""
		configuration_data_json = {"es_host": self.es_host, "verificate_certificate_ssl": self.verificate_certificate_ssl}
		if self.verificate_certificate_ssl and self.certificate_file:
			configuration_data_json["certificate_file"] = self.certificate_file
		configuration_data_json["use_authentication"] = self.use_authentication
		if self.use_authentication and self.authentication_method in METHOD_FIELDS:
			configuration_data_json["authentication_method"] = self.authentication_method
			for tag in METHOD_FIELDS[self.authentication_method]:
				field = CREDENTIAL_FIELDS[tag][0]
				configuration_data_json[field] = getattr(self, field)
		return configuration_data_json


	def convert_dict_to_object(self, configuration_data: dict) -> None:
		"""
		Method that converts a dictionary into an object of type libPyConfiguration (the data is validated).

		Parameters:
			configuration_data (dict): Dictionary to convert.
		"""
		if not isinstance(configuration_data, dict):
			raise ValueError("Invalid configuration file.")
		hosts = configuration_data.get("es_host")
		if not isinstance(hosts, list) or not hosts or not all(isinstance(host, str) for host in hosts):
			raise ValueError("Invalid es_host in the configuration file.")
		verify = configuration_data.get("verificate_certificate_ssl", False)
		use_authentication = configuration_data.get("use_authentication", False)
		if not isinstance(verify, bool) or not isinstance(use_authentication, bool):
			raise ValueError("Invalid boolean value in the configuration file.")
		certificate_file = configuration_data.get("certificate_file") if verify else None
		if certificate_file is not None and not isinstance(certificate_file, str):
			raise ValueError("Invalid certificate_file in the configuration file.")
		method = configuration_data.get("authentication_method") if use_authentication else None
		if use_authentication and method not in AUTH_METHOD_NAMES:
			raise ValueError("Invalid authentication_method in the configuration file.")
		credentials = {}
		if method is not None:
			for tag in METHOD_FIELDS[method]:
				field = CREDENTIAL_FIELDS[tag][0]
				credentials[field] = self._encrypted_field(configuration_data, field)
		self.es_host = hosts
		self.verificate_certificate_ssl = verify
		self.certificate_file = certificate_file
		self.use_authentication = use_authentication
		self.authentication_method = method
		self._clear_credentials()
		for field, value in credentials.items():
			setattr(self, field, value)


	# --- File management -----------------------------------------------------------------------
	def create_file(self, configuration_data: dict, configuration_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that creates the YAML file corresponding to the configuration.

		Parameters:
			configuration_data (dict): Data to save in the YAML file.
			configuration_file (str): Configuration file path.
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		try:
			self.utils.create_yaml_file(configuration_data, configuration_file)
			self.utils.change_owner(configuration_file, user, group, "600")
			if configuration_data.get("verificate_certificate_ssl"):
				self._secure_certificate(configuration_data.get("certificate_file"), user, group)
			self._log("Configuration created", 2, "_createConfiguration", log_file_name, user, group)
			self.dialog.create_message("\nConfiguration created.", 7, 50, "Notification Message")
		except DialogCancelled:
			pass
		except Exception as exception:
			self.dialog.create_message("\nError creating configuration. For more information, see the logs.", 8, 50, "Error Message")
			self._log(exception, 4, "_createConfiguration", log_file_name, user, group)


	def modify_configuration(self, configuration_file: str, key_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that modifies the configuration.

		Parameters:
			configuration_file (str): Configuration file path.
			key_file (str): Key file path.
			log_file_name (str): Log file path.
			user (str): Owner user (also expected owner of the key file).
			group (str): Owner group.
		"""
		try:
			options = self.dialog.create_checklist("Select one or more options:", 10, 70, CONFIGURATION_FIELDS, "Configuration Fields")
			original_data = self.utils.read_yaml_file(configuration_file)
			self.convert_dict_to_object(deepcopy(original_data))
			if "Host" in options:
				self.modify_es_host(log_file_name, user, group)
			if "Certificate SSL" in options:
				self.modify_verificate_certificate(log_file_name, user, group)
			if "Authentication" in options:
				self.modify_use_authentication(key_file, log_file_name, user, group)
			if self.use_authentication and not self.utils.validate_https_urls(self.es_host):
				self.dialog.create_message("\nAuthentication requires all ElasticSearch hosts to use HTTPS. Changes were not saved.", 9, 55, "Error Message")
				return
			if self.verificate_certificate_ssl and not self.utils.validate_https_urls(self.es_host):
				self.verificate_certificate_ssl = False
				self.certificate_file = None
			new_data = self.convert_object_to_dict()
			if new_data == original_data:
				self.dialog.create_message("\nConfiguration not modified.", 7, 50, "Notification Message")
				return
			self.utils.create_yaml_file(new_data, configuration_file)
			if new_data.get("verificate_certificate_ssl"):
				self._secure_certificate(new_data.get("certificate_file"), user, group)
			self._log("Configuration modified", 3, "_modifyConfiguration", log_file_name, user, group)
			self.dialog.create_message("\nConfiguration modified.", 7, 50, "Notification Message")
		except DialogCancelled:
			pass
		except Exception as exception:
			self.dialog.create_message("\nError modifying configuration. For more information, see the logs.", 8, 50, "Error Message")
			self._log(exception, 4, "_modifyConfiguration", log_file_name, user, group)


	# --- Modification --------------------------------------------------------------------------
	def modify_es_host(self, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that modifies ElasticSearch master nodes.

		Parameters:
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		option = self.dialog.create_menu("Select a option:", 10, 50, ES_HOST_OPTIONS, "ElasticSearch Host Menu")
		match option:
			case "1":
				new_hosts = [host for host in self._ask_new_hosts("Add ElasticSearch Hosts") if host not in self.es_host]
				if not new_hosts:
					self.dialog.create_message("\nThe hosts entered already exist.", 7, 50, "Notification Message")
					return
				self.es_host.extend(new_hosts)
				self._log(f"Added ElasticSearch Hosts: {','.join(new_hosts)}", 3, "_modifyConfiguration", log_file_name, user, group)
			case "2":
				tuple_to_form = self.utils.convert_list_to_tuple(self.es_host, "ES Host")
				self.es_host = self._unique(self.dialog.create_url_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "Modify ElasticSearch Hosts"))
				self._log(f"Modified ElasticSearch Hosts: {','.join(self.es_host)}", 3, "_modifyConfiguration", log_file_name, user, group)
			case "3":
				tuple_to_rc = self.utils.convert_list_to_tuple_rc(self.es_host, "ES Host")
				options = self.dialog.create_checklist("Select one or more options:", 15, 50, tuple_to_rc, "Remove ElasticSearch Hosts")
				text = self.utils.get_str_from_list(options, "Selected ElasticSearch Hosts:")
				self.dialog.create_scrollbox(text, 15, 60, "Remove ElasticSearch Hosts")
				if not self.dialog.create_yes_or_no("\nAre you sure to remove the selected ElasticSearch Hosts?\n\n** This action cannot be undone.", 10, 50, "Remove ElasticSearch Hosts"):
					return
				remaining = [host for host in self.es_host if host not in options]
				if not remaining:
					self.dialog.create_message("\nAt least one host is required.", 7, 50, "Error Message")
					return
				self.es_host = remaining
				self._log(f"Removed ElasticSearch Hosts: {','.join(options)}", 3, "_modifyConfiguration", log_file_name, user, group)


	def modify_verificate_certificate(self, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that updates or modifies the configuration related to the use of the TLS/SSL protocol.

		Parameters:
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		if self.verificate_certificate_ssl:
			option = self.dialog.create_radiolist("Select a option:", 9, 65, OPTIONS_VERIFICATE_CERTIFICATE_TRUE, "Certificate Verification")
			if option == "Disable":
				if not self.dialog.create_yes_or_no("\nDisabling certificate verification exposes the connection to man-in-the-middle attacks.\n\nContinue?", 10, 55, "Certificate Verification"):
					return
				self.verificate_certificate_ssl = False
				self.certificate_file = None
				self._log("SSL certificate verification has been disabled", 3, "_modifyConfiguration", log_file_name, user, group)
			elif option == "Certificate File":
				self.certificate_file = self._select_certificate()
				self._log(f"SSL certificate changed: {self.certificate_file}", 3, "_modifyConfiguration", log_file_name, user, group)
		else:
			if not self.utils.validate_https_urls(self.es_host):
				self.dialog.create_message("\nCertificate verification is only available when all hosts use HTTPS.", 8, 55, "Error Message")
				return
			self.dialog.create_radiolist("Select a option:", 8, 70, OPTIONS_VERIFICATE_CERTIFICATE_FALSE, "Certificate Verification")
			self.certificate_file = self._select_certificate()
			self.verificate_certificate_ssl = True
			self._log("SSL certificate verification has been enabled", 3, "_modifyConfiguration", log_file_name, user, group)


	def modify_use_authentication(self, key_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that updates or modifies the configuration related to the use of an authentication method
		(the current values are never decrypted or displayed).

		Parameters:
			key_file (str): Key file path.
			log_file_name (str): Log file path.
			user (str): Owner user (also expected owner of the key file).
			group (str): Owner group.
		"""
		if not self.use_authentication:
			self.dialog.create_radiolist("Select a option:", 8, 55, OPTIONS_AUTHENTICATION_FALSE, "Authentication Method")
			if not self._https_required():
				return
			method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
			self._with_passphrase(key_file, user, lambda passphrase: self._ask_credentials(method, passphrase))
			self.use_authentication = True
			self._log(f"Authentication method usage has been enabled: {method}", 3, "_modifyConfiguration", log_file_name, user, group)
			return

		option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_TRUE, "Authentication Method")
		if option == "Disable":
			self.use_authentication = False
			self.authentication_method = None
			self._clear_credentials()
			self._log("Authentication method usage has been disabled", 3, "_modifyConfiguration", log_file_name, user, group)
			return

		current_method = self.authentication_method
		option = self.dialog.create_radiolist("Select a option:", 9, 60, OPTIONS_AUTHENTICATION_MODIFY, current_method)
		if option == "Switch":
			new_method = API_KEY if current_method == HTTP_AUTH else HTTP_AUTH
			self._with_passphrase(key_file, user, lambda passphrase: self._ask_credentials(new_method, passphrase))
			self._log(f"{current_method} disabled. {new_method} enabled.", 3, "_modifyConfiguration", log_file_name, user, group)
		elif option == "Data":
			choices = OPTIONS_HTTP_AUTHENTICATION if current_method == HTTP_AUTH else OPTIONS_API_KEY
			selected = self.dialog.create_checklist("Select one or more options:", 9, 55, choices, current_method)

			def update(passphrase: bytearray) -> list:
				changed = []
				for tag in selected:
					setattr(self, CREDENTIAL_FIELDS[tag][0], self._encrypt_secret(passphrase, tag))
					changed.append(CREDENTIAL_FIELDS[tag][3])
				return changed

			for label in self._with_passphrase(key_file, user, update):
				self._log(f"{label} changed", 3, "_modifyConfiguration", log_file_name, user, group)


	# --- Display -------------------------------------------------------------------------------
	def display_configuration(self, configuration_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that displays the contents of the configuration file (sensitive data masked).

		Parameters:
			configuration_file (str): Configuration file path.
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		try:
			configuration_data = self.utils.convert_yaml_to_str(configuration_file)
			self.dialog.create_scrollbox("\nData:\n\n" + configuration_data, 18, 70, "Configuration")
		except DialogCancelled:
			pass
		except Exception as exception:
			self.dialog.create_message("\nError displaying configuration. For more information, see the logs.", 8, 50, "Error Message")
			self._log(exception, 4, "_displayConfiguration", log_file_name, user, group)