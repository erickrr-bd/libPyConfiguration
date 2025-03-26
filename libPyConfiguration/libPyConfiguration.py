"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyConfiguration
libPyConfiguration v1.0 - March 2025
"""
from os import path
from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog
from dataclasses import dataclass, field

@dataclass
class libPyConfiguration:
	"""
	Easy creation of configuration files for Python and ElasticSearch.
	"""

	es_host: list = field(default_factory = list)
	verificate_certificate_ssl: bool = False
	certificate_file: str = None
	use_authentication: bool = False
	authentication_method: str = None
	http_authentication_user: tuple = None
	http_authentication_password: tuple = None
	api_key_id: tuple = None
	api_key: tuple = None


	def __init__(self, backtitle: str = ""):
		"""
		Class constructor.
		"""
		self.logger = libPyLog()
		self.utils = libPyUtils()
		self.dialog = libPyDialog(backtitle)


	def define_es_host(self) -> None:
		"""
		Method that defines the master nodes of the cluster.
		"""
		total_master_nodes = self.dialog.create_integer_inputbox("Enter the total number of master nodes:", 8, 50, "1")
		tuple_to_form = self.utils.generate_tuple_to_form(int(total_master_nodes), "ES Host")
		self.es_host = self.dialog.create_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "ElasticSearch Hosts", True, validation_type = 2)


	def define_verificate_certificate(self) -> None:
		"""
		Method that defines whether the SSL certificate needs to be verified or not.
		"""
		if self.utils.validate_https_or_http(self.es_host):
			verificate_certificate_ssl_yn = self.dialog.create_yes_or_no("\nIs SSL certificate verification required?\n\n**Note: Available only when using HTTPS.", 9, 50, "Certificate SSL Verification")
			if verificate_certificate_ssl_yn == "ok":
				self.verificate_certificate_ssl = True
				self.certificate_file = self.dialog.create_file("/etc", 8, 50, "Select the CA certificate:", [".pem"])


	def define_use_authentication(self, key_file: str) -> None:
		"""
		Method that defines whether an authentication method is required or not.

		Parameters:
			key_file (str): Key file path.
		"""
		AUTHENTICATION_METHOD_OPTIONS = [("HTTP Authentication", "Use HTTP Authentication", 0), ("API Key", "Use API Key", 0)]

		use_authentication_yn = self.dialog.create_yes_or_no("\nIs an authentication method (HTTP Authentication or API Key) required?", 8, 50, "Authentication Method")
		if use_authentication_yn == "ok":
			self.use_authentication = True
			passphrase = self.utils.get_passphrase(key_file)
			self.authentication_method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
			if self.authentication_method == "HTTP Authentication":
				self.http_authentication_user = self.utils.encrypt_data(self.dialog.create_inputbox("Enter username:", 8, 50, "http_user"), passphrase)
				self.http_authentication_password = self.utils.encrypt_data(self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True), passphrase)
			elif self.authentication_method == "API Key":
				self.api_key_id = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
				self.api_key = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)


	def convert_object_to_dict(self) -> dict:
		"""
		Method that converts an object of type libPyConfiguration into a dictionary.

		Returns:
			configuration_data_json (dict): Dictionary with the object's data.
		"""
		configuration_data_json = {
			"es_host": self.es_host
		}

		configuration_data_json.update({"verificate_certificate_ssl" : self.verificate_certificate_ssl})
		if self.verificate_certificate_ssl:
			configuration_data_json.update({"certificate_file": self.certificate_file})
		configuration_data_json.update({"use_authentication" : self.use_authentication})
		if self.use_authentication:
			if self.authentication_method == "HTTP Authentication":
				configuration_data_json.update({"authentication_method" : self.authentication_method, "http_authentication_user" : self.http_authentication_user, "http_authentication_password" : self.http_authentication_password})
			elif self.authentication_method == "API Key":
				configuration_data_json.update({"authentication_method" : self.authentication_method, "api_key_id" : self.api_key_id, "api_key" : self.api_key})
		return configuration_data_json


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
			self.utils.change_owner(configuration_file, user, group, "644")
			if configuration_data["verificate_certificate_ssl"]:
				self.utils.change_owner(configuration_data["certificate_file"], user, group, "644")
			if path.exists(configuration_file):
				self.dialog.create_message("\nConfiguration created.", 7, 50, "Notification Message")
				self.logger.create_log("Configuration created", 2, "__createConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except Exception as exception:
			self.dialog.create_message("\nError creating configuration. For more information, see the logs.", 8, 50, "Error Message")
			self.logger.create_log(exception, 4, "_createConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except KeyboardInterrupt:
			pass
		finally:
			raise KeyboardInterrupt("Exit")


	def convert_dict_to_object(self, configuration_data: dict) -> None:
		"""
		Method that converts a dictionary into an object of type libPyConfiguration.

		Parameters:
			configuration_data (dict): Dictionary to convert.
		"""
		self.es_host = configuration_data["es_host"]
		self.verificate_certificate_ssl = configuration_data["verificate_certificate_ssl"]
		self.use_authentication = configuration_data["use_authentication"]

		if configuration_data["verificate_certificate_ssl"]:
			self.certificate_file = configuration_data["certificate_file"]
		if configuration_data["use_authentication"]:
			self.authentication_method = configuration_data["authentication_method"]
			if configuration_data["authentication_method"] == "HTTP Authentication":
				self.http_authentication_user = configuration_data["http_authentication_user"]
				self.http_authentication_password = configuration_data["http_authentication_password"]
			elif configuration_data["authentication_method"] == "API Key":
				self.api_key_id = configuration_data["api_key_id"]
				self.api_key = configuration_data["api_key"]


	def modify_configuration(self, configuration_file: str, key_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that modifies the configuration.

		Parameters:
			configuration_file (str): Configuration file path.
			key_file (str): Key file path.
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		CONFIGURATION_FIELDS = [("Host", "ElasticSearch Host", 0), ("Certificate SSL", "Enable or disable certificate verification", 0), ("Authentication", "Enable or disable authentication method", 0)]
		
		try:
			options = self.dialog.create_checklist("Select one or more options:", 10, 70, CONFIGURATION_FIELDS, "Configuration Fields")
			configuration_data = self.utils.read_yaml_file(configuration_file)
			self.convert_dict_to_object(configuration_data)
			original_hash = self.utils.get_hash_from_file(configuration_file)
			if "Host" in options:
				self.modify_es_host()
			if "Certificate SSL" in options:
				self.modify_verificate_certificate()
			if "Authentication" in options:
				self.modify_use_authentication(key_file)
			configuration_data = self.convert_object_to_dict()
			self.utils.create_yaml_file(configuration_data, configuration_file)
			new_hash = self.utils.get_hash_from_file(configuration_file)
			if new_hash == original_hash:
				self.dialog.create_message("\nConfiguration not modified.", 7, 50, "Notification Message")
			else:
				self.dialog.create_message("\nConfiguration modified.", 7, 50, "Notification Message")
				self.logger.create_log("Configuration modified.", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group )
		except Exception as exception:
			self.dialog.create_message("\nError modifying configuration. For more information, see the logs.", 8, 50, "Error Message")
			self.logger.create_log(exception, 4, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except KeyboardInterrupt:
			pass
		finally:
			raise KeyboardInterrupt("Exit")


	def modify_es_host(self) -> None:
		"""
		Method that modifies ElasticSearch master nodes.
		"""
		ES_HOST_OPTIONS = [("1", "Add New Hosts"), ("2", "Modify Hosts"), ("3", "Remove Hosts")]

		option = self.dialog.create_menu("Select a option:", 10, 50, ES_HOST_OPTIONS, "ElasticSearch Host Menu")
		match option:
			case "1":		
				total_master_nodes = self.dialog.create_integer_inputbox("Enter the total number of master nodes:", 8, 50, "1")
				tuple_to_form = self.utils.generate_tuple_to_form(int(total_master_nodes), "ES Host")
				es_host = self.dialog.create_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "Add ElasticSearch Hosts", True, validation_type = 2)
				self.es_host.extend(es_host)
			case "2":
				tuple_to_form = self.utils.convert_list_to_tuple(self.es_host, "ES Host")
				self.es_host = self.dialog.create_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "Modify ElasticSearch Hosts", True, validation_type = 2)
			case "3":
				tuple_to_rc = self.utils.convert_list_to_tuple_rc(self.es_host, "ES Host")
				options = self.dialog.create_checklist("Select one or more options:", 15, 50, tuple_to_rc, "Remove ElasticSearch Hosts")
				text = self.utils.get_str_from_list(options, "Selected ElasticSearch Hosts:")
				self.dialog.create_scrollbox(text, 15, 60, "Remove ElasticSearch Hosts")
				es_host_yn = self.dialog.create_yes_or_no("\nAre you sure to remove the selected ElasticSearch Hosts?\n\n** This action cannot be undone.", 10, 50, "Remove ElasticSearch Hosts")
				if es_host_yn == "ok":
					[self.es_host.remove(option) for option in options]


	def modify_verificate_certificate(self) -> None:
		"""
		Method that updates or modifies the configuration related to the use of the TLS/SSL protocol.
		"""
		OPTIONS_VERIFICATE_CERTIFICATE_TRUE = [("Disable", "Disable certificate verification", 0), ("Certificate File", "Change certificate file", 0)]

		OPTIONS_VERIFICATE_CERTIFICATE_FALSE = [("Enable", "Enable certificate verification", 0)]

		if self.verificate_certificate_ssl:
			option = self.dialog.create_radiolist("Select a option:", 9, 65, OPTIONS_VERIFICATE_CERTIFICATE_TRUE, "Certificate Verification")
			if option == "Disable":
				self.verificate_certificate_ssl = False
				self.certificate_file = None
			elif option == "Certificate File":
				self.certificate_file = self.dialog.create_file(self.certificate_file, 8, 50, "Select the CA certificate:", [".pem"])
		else:
			option = self.dialog.create_radiolist("Select a option:", 8, 70, OPTIONS_VERIFICATE_CERTIFICATE_FALSE, "Certificate Verification")
			if option == "Enable":
				self.verificate_certificate_ssl = True
				self.certificate_file = self.dialog.create_file("/etc", 8, 50, "Select the CA certificate:", [".pem"])


	def modify_use_authentication(self, key_file: str) -> None:
		"""
		Method that updates or modifies the configuration related to the use of an authentication method.

		Parameters:
			key_file (str): Key file path.
		"""
		OPTIONS_AUTHENTICATION_TRUE = [("Disable", "Disable authentication method", 0), ("Method", "Modify authentication method", 0)]

		OPTIONS_AUTHENTICATION_FALSE = [("Enable", "Enable authentication", 0)]

		OPTIONS_AUTHENTICATION_MODIFY = [("Disable", "Disable authentication method", 0), ("Data", "Modify authentication method data", 0)]

		OPTIONS_HTTP_AUTHENTICATION = [("Username", "Username for HTTP Authentication", 0), ("Password", "User password", 0)]

		OPTIONS_API_KEY = [("ID", "API Key ID", 0), ("API Key", "API Key", 0)]

		AUTHENTICATION_METHOD_OPTIONS = [("HTTP Authentication", "Use HTTP Authentication", 0), ("API Key", "Use API Key", 0)]

		if self.use_authentication:
			option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_TRUE, "Authentication Method")
			if option == "Disable":
				self.use_authentication = False
				if self.authentication_method == "HTTP Authentication":
					self.http_authentication_user = None
					self.http_authentication_password = None
				elif self.authentication_method == "API Key":
					self.api_key_id = None
					self.api_key = None
				self.authentication_method = None
			elif option == "Method":
				passphrase = self.utils.get_passphrase(key_file)
				if self.authentication_method == "HTTP Authentication":
					option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_MODIFY, "HTTP Authentication")
					if option == "Disable":
						self.http_authentication_user = None
						self.http_authentication_password = None
						self.authentication_method = "API Key"
						self.api_key_id = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
						self.api_key = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
					elif option == "Data":
						options = self.dialog.create_checklist("Select one or more options:", 9, 55, OPTIONS_HTTP_AUTHENTICATION, "HTTP Authentication")
						if "Username" in options:
							self.http_authentication_user = self.utils.encrypt_data(self.dialog.create_inputbox("Enter username:", 8, 50, "http_user"), passphrase)
						if "Password" in options:
							self.http_authentication_password = self.utils.encrypt_data(self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True), passphrase)
				elif self.authentication_method == "API Key":
					option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_MODIFY, "API Key")
					if option == "Disable":
						self.api_key_id = None
						self.api_key = None
						self.authentication_method = "HTTP Authentication"
						self.http_authentication_user = self.utils.encrypt_data(self.dialog.create_inputbox("Enter username:", 8, 50, "http_user"), passphrase)
						self.http_authentication_password = self.utils.encrypt_data(self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True), passphrase)
					elif option == "Data":
						options = self.dialog.create_checklist("Select one or more options:", 9, 55, OPTIONS_API_KEY, "API Key")
						if "ID" in options:
							self.api_key_id = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
						if "API Key" in options:
							self.api_key = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
		else:
			option = self.dialog.create_radiolist("Select a option:", 8, 55, OPTIONS_AUTHENTICATION_FALSE, "Authentication Method")
			if option == "Enable":
				self.use_authentication = True
				passphrase = self.utils.get_passphrase(key_file)
				self.authentication_method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
				if self.authentication_method == "HTTP Authentication":
					self.http_authentication_user = self.utils.encrypt_data(self.dialog.create_inputbox("Enter username:", 8, 50, "http_user"), passphrase)
					self.http_authentication_password = self.utils.encrypt_data(self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True), passphrase)
				elif self.authentication_method == "API Key":
					self.api_key_id = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
					self.api_key = self.utils.encrypt_data(self.dialog.create_inputbox("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)


	def display_configuration(self, configuration_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that displays the contents of the configuration file.

		Parameters:
			configuration_file (str): Configuration file path.
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		try:
			configuration_data = self.utils.convert_yaml_to_str(configuration_file)
			text = "\nData:\n\n" + configuration_data
			self.dialog.create_scrollbox(text, 18, 70, "Configuration")
		except Exception as exception:
			self.dialog.create_message("\nError displaying configuration. For more information, see the logs.", 8, 50, "Error Message")
			self.logger.create_log(exception, 4, "_displayConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except KeyboardInterrupt:
			pass
		finally:
			raise KeyboardInterrupt("Exit")