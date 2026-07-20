"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyConfiguration
libPyConfiguration v1.2 - July 2026
Dynamic, memory-secure configuration management engine written in Python.
"""
from os import path
from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog

class libPyConfiguration:

	def __init__(self, backtitle: str = "") -> None:
		"""
		Class constructor.

		Parameters:
			backtitle (str): Text displayed in the background.
		"""
		self.es_host = []
		self.api_key = ()
		self.api_key_id = ()
		self.logger = libPyLog()
		self.utils = libPyUtils()
		self.certificate_file = None
		self.use_authentication = False
		self.authentication_method = None
		self.http_authentication_user = ()
		self.dialog = libPyDialog(backtitle)
		self.http_authentication_password = ()
		self.verificate_certificate_ssl = False


	def define_es_host(self) -> None:
		"""
		Method that defines the master nodes of the cluster.
		"""
		total_master_nodes = self.dialog.create_integer_inputbox("Enter the total number of master nodes:", 8, 50, "1")
		if not total_master_nodes:
			return
		tuple_to_form = self.utils.generate_tuple_to_form(int(total_master_nodes), "ES Host")
		hosts_data = self.dialog.create_url_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "ElasticSearch Hosts")
		if hosts_data:
			self.es_host = hosts_data


	def define_verificate_certificate(self) -> None:
		"""
		Method that defines whether the SSL certificate needs to be verified or not.
		"""
		if self.utils.validate_https_or_http(self.es_host):
			verificate_certificate_ssl_yn = self.dialog.create_yes_or_no("\nIs SSL certificate verification required?\n\n**Note: Available only when using HTTPS.", 9, 50, "Certificate SSL Verification")
			if verificate_certificate_ssl_yn:
				self.verificate_certificate_ssl = True
				selected_file = self.dialog.create_file("/opt/Snap-Tool", 8, 50, "Select the CA certificate:", [".pem"])
				if selected_file:
					self.certificate_file = selected_file


	def define_use_authentication(self, key_file: str) -> None:
		"""
		Method that defines whether an authentication method is required or not.

		Parameters:
			key_file (str): Key file path.
		"""
		user = None
		password = None
		api_id = None
		api_secret = None
		passphrase = None

		AUTHENTICATION_METHOD_OPTIONS = [("HTTP Authentication", "Use HTTP Authentication", 0), ("API Key", "Use API Key", 0)]
		
		use_authentication_yn = self.dialog.create_yes_or_no("\nIs an authentication method (HTTP Authentication or API Key) required?", 8, 50, "Authentication Method")
		if use_authentication_yn:
			self.use_authentication = True
			passphrase = self.utils.get_passphrase(key_file)
			self.authentication_method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
			if not self.authentication_method:
				return
			try:
				if self.authentication_method == "HTTP Authentication":
					user = self.dialog.create_inputbox("Enter username:", 8, 50, "http_user")
					password = self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True)
					if user and password:
						self.http_authentication_user = self.utils.encrypt_data(user, passphrase)
						self.http_authentication_password = self.utils.encrypt_data(password, passphrase)
				elif self.authentication_method == "API Key":
					api_id = self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "api_id")
					api_secret = self.dialog.create_inputbox("Enter the API Key:", 8, 50, "api_secret")
					if api_id and api_secret:
						self.api_key_id = self.utils.encrypt_data(api_id, passphrase)
						self.api_key = self.utils.encrypt_data(api_secret, passphrase)
			finally:
				user = None
				password = None
				api_id = None
				api_secret = None
				passphrase = None
				del user
				del password
				del api_id
				del api_secret
				del passphrase


	def convert_object_to_dict(self) -> dict:
		"""
		Method that converts an object of type libPyConfiguration into a dictionary.

		Returns:
			configuration_data_json (dict): Dictionary with the object's data.
		"""
		configuration_data_json = {
			"es_host": self.es_host,
			"verificate_certificate_ssl": self.verificate_certificate_ssl
		}

		if self.verificate_certificate_ssl and self.certificate_file:
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
			self.utils.change_owner(configuration_file, user, group, "600")
			if configuration_data.get("verificate_certificate_ssl") and configuration_data.get("certificate_file"):
				self.utils.change_owner(configuration_data["certificate_file"], user, group, "600")
			if path.exists(configuration_file):
				self.dialog.create_message("\nConfiguration created.", 7, 50, "Notification Message")
				self.logger.create_log("Configuration created", 2, "__createConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except Exception as exception:
			self.dialog.create_message("\nError creating configuration. For more information, see the logs.", 8, 50, "Error Message")
			self.logger.create_log(exception, 4, "_createConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except KeyboardInterrupt:
			pass


	def convert_dict_to_object(self, configuration_data: dict) -> None:
		"""
		Method that converts a dictionary into an object of type libPyConfiguration.

		Parameters:
			configuration_data (dict): Dictionary to convert.
		"""
		self.es_host = configuration_data.get("es_host", [])
		self.verificate_certificate_ssl = configuration_data.get("verificate_certificate_ssl", False)
		self.use_authentication = configuration_data.get("use_authentication", False)
		if configuration_data["verificate_certificate_ssl"]:
			self.certificate_file = configuration_data.get("certificate_file", None)
		if configuration_data["use_authentication"]:
			self.authentication_method = configuration_data.get("authentication_method", None)
			if configuration_data["authentication_method"] == "HTTP Authentication":
				self.http_authentication_user = configuration_data.get("http_authentication_user", ())
				self.http_authentication_password = configuration_data.get("http_authentication_password", ())
			elif configuration_data["authentication_method"] == "API Key":
				self.api_key_id = configuration_data.get("api_key_id", ())
				self.api_key = configuration_data.get("api_key", ())


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
			if not options:
				return
			configuration_data = self.utils.read_yaml_file(configuration_file)
			self.convert_dict_to_object(configuration_data)
			original_hash = self.utils.get_hash_from_file(configuration_file)
			if "Host" in options:
				self.modify_es_host(log_file_name, user, group)
			if "Certificate SSL" in options:
				self.modify_verificate_certificate(log_file_name, user, group)
			if "Authentication" in options:
				self.modify_use_authentication(key_file, log_file_name, user, group)
			configuration_data = self.convert_object_to_dict()
			self.utils.create_yaml_file(configuration_data, configuration_file)
			new_hash = self.utils.get_hash_from_file(configuration_file)
			if new_hash == original_hash:
				self.dialog.create_message("\nConfiguration not modified.", 7, 50, "Notification Message")
			else:
				self.dialog.create_message("\nConfiguration modified.", 7, 50, "Notification Message")
		except Exception as exception:
			self.dialog.create_message("\nError modifying configuration. For more information, see the logs.", 8, 50, "Error Message")
			self.logger.create_log(exception, 4, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		except KeyboardInterrupt:
			pass


	def modify_es_host(self, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that modifies ElasticSearch master nodes.

		Parameters:
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		ES_HOST_OPTIONS = [("1", "Add New Hosts"), ("2", "Modify Hosts"), ("3", "Remove Hosts")]

		option = self.dialog.create_menu("Select a option:", 10, 50, ES_HOST_OPTIONS, "ElasticSearch Host Menu")
		if not option:
			return
		match option:
			case "1":		
				total_master_nodes = self.dialog.create_integer_inputbox("Enter the total number of master nodes:", 8, 50, "1")
				if not total_master_nodes:
					return
				tuple_to_form = self.utils.generate_tuple_to_form(int(total_master_nodes), "ES Host")
				es_host = self.dialog.create_url_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "Add ElasticSearch Hosts")
				if not es_host:
					return
				self.es_host.extend(es_host)
				self.logger.create_log(f"Added ElasticSearch Hosts: {','.join(es_host)}", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
			case "2":
				tuple_to_form = self.utils.convert_list_to_tuple(self.es_host, "ES Host")
				new_hosts = self.dialog.create_url_form("Enter ElasticSearch Hosts:", tuple_to_form, 15, 50, "Modify ElasticSearch Hosts")
				if not new_hosts:
					return
				self.es_host = new_hosts
				self.logger.create_log(f"Modified ElasticSearch Hosts: {','.join(self.es_host)}", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
			case "3":
				tuple_to_rc = self.utils.convert_list_to_tuple_rc(self.es_host, "ES Host")
				options = self.dialog.create_checklist("Select one or more options:", 15, 50, tuple_to_rc, "Remove ElasticSearch Hosts")
				if not options:
					return
				text = self.utils.get_str_from_list(options, "Selected ElasticSearch Hosts:")
				self.dialog.create_scrollbox(text, 15, 60, "Remove ElasticSearch Hosts")
				es_host_yn = self.dialog.create_yes_or_no("\nAre you sure to remove the selected ElasticSearch Hosts?\n\n** This action cannot be undone.", 10, 50, "Remove ElasticSearch Hosts")
				if es_host_yn:
					[self.es_host.remove(option) for option in options]
				self.logger.create_log(f"Removed ElasticSearch Hosts: {','.join(options)}", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)


	def modify_verificate_certificate(self, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that updates or modifies the configuration related to the use of the TLS/SSL protocol.

		Parameters:
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		OPTIONS_VERIFICATE_CERTIFICATE_TRUE = [("Disable", "Disable certificate verification", 0), ("Certificate File", "Change certificate file", 0)]
		OPTIONS_VERIFICATE_CERTIFICATE_FALSE = [("Enable", "Enable certificate verification", 0)]

		if self.verificate_certificate_ssl:
			option = self.dialog.create_radiolist("Select a option:", 9, 65, OPTIONS_VERIFICATE_CERTIFICATE_TRUE, "Certificate Verification")
			if not option:
				return
			if option == "Disable":
				self.verificate_certificate_ssl = False
				self.certificate_file = None
				self.logger.create_log("SSL certificate verification has been disabled", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
			elif option == "Certificate File":
				current_cert = self.certificate_file if self.certificate_file else "/opt/Snap-Tool"
				new_cert = self.dialog.create_file(current_cert, 8, 50, "Select the CA certificate:", [".pem"])
				if new_cert:
					self.certificate_file = new_cert
					self.logger.create_log(f"SSL certificate changed: {self.certificate_file}", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
		else:
			option = self.dialog.create_radiolist("Select a option:", 8, 70, OPTIONS_VERIFICATE_CERTIFICATE_FALSE, "Certificate Verification")
			if option == "Enable":
				self.verificate_certificate_ssl = True
				cert = self.dialog.create_file("/opt/Snap-Tool", 8, 50, "Select the CA certificate:", [".pem"])
				if cert:
					self.certificate_file = cert
					self.logger.create_log("SSL certificate verification has been enabled", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)


	def modify_use_authentication(self, key_file: str, log_file_name: str, user: str = None, group: str = None) -> None:
		"""
		Method that updates or modifies the configuration related to the use of an authentication method.

		Parameters:
			key_file (str): Key file path.
			log_file_name (str): Log file path.
			user (str): Owner user.
			group (str): Owner group.
		"""
		user = None
		password = None
		api_id = None
		api_secret = None
		passphrase = None

		OPTIONS_AUTHENTICATION_TRUE = [("Disable", "Disable authentication method", 0), ("Method", "Modify authentication method", 0)]
		OPTIONS_AUTHENTICATION_FALSE = [("Enable", "Enable authentication", 0)]
		OPTIONS_AUTHENTICATION_MODIFY = [("Disable", "Disable authentication method", 0), ("Data", "Modify authentication method data", 0)]
		OPTIONS_HTTP_AUTHENTICATION = [("Username", "Username for HTTP Authentication", 0), ("Password", "User password", 0)]
		OPTIONS_API_KEY = [("ID", "API Key ID", 0), ("API Key", "API Key", 0)]
		AUTHENTICATION_METHOD_OPTIONS = [("HTTP Authentication", "Use HTTP Authentication", 0), ("API Key", "Use API Key", 0)]

		if self.use_authentication:
			option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_TRUE, "Authentication Method")
			if not option:
				return
			if option == "Disable":
				self.use_authentication = False
				self.http_authentication_user = ()
				self.http_authentication_password = ()
				self.api_key_id = ()
				self.api_key = ()
				self.authentication_method = None
				self.logger.create_log("Authentication method usage has been disabled", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
			elif option == "Method":
				try:
					passphrase = self.utils.get_passphrase(key_file)
					if self.authentication_method == "HTTP Authentication":
						option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_MODIFY, "HTTP Authentication")
						if not option:
							return
						if option == "Disable":
							self.http_authentication_user = ()
							self.http_authentication_password = ()
							self.authentication_method = "API Key"
							api_id = self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "api_id")
							api_secret = self.dialog.create_inputbox("Enter the API Key:", 8, 50, "api_secret")
							if api_id and api_secret:
								self.api_key_id = self.utils.encrypt_data(api_id, passphrase)
								self.api_key = self.utils.encrypt_data(api_secret, passphrase)
							self.logger.create_log("HTTP Authentication disabled. API Key authentication enabled.", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
						elif option == "Data":
							options = self.dialog.create_checklist("Select one or more options:", 9, 55, OPTIONS_HTTP_AUTHENTICATION, "HTTP Authentication")
							if not options:
								return
							if "Username" in options:
								user = self.dialog.create_inputbox("Enter username:", 8, 50, "http_user")
								if user:
									self.http_authentication_user = self.utils.encrypt_data(user, passphrase)
									self.logger.create_log("Username changed", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
							if "Password" in options:
								password = self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True)
								if password:
									self.http_authentication_password = self.utils.encrypt_data(password, passphrase)
									self.logger.create_log("Password changed", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
					elif self.authentication_method == "API Key":
						option = self.dialog.create_radiolist("Select a option:", 9, 55, OPTIONS_AUTHENTICATION_MODIFY, "API Key")
						if not option:
							return
						if option == "Disable":
							self.api_key_id = ()
							self.api_key = ()
							self.authentication_method = "HTTP Authentication"
							user = self.dialog.create_inputbox("Enter username:", 8, 50, "http_user")
							password = self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True)
							if user and password:
								self.http_authentication_user = self.utils.encrypt_data(user, passphrase)
								self.http_authentication_password = self.utils.encrypt_data(password, passphrase)
								self.logger.create_log("API Key authentication disabled. HTTP Authentication enabled.", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
						elif option == "Data":
							options = self.dialog.create_checklist("Select one or more options:", 9, 55, OPTIONS_API_KEY, "API Key")
							if not options:
								return
							if "ID" in options:
								api_id = self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "api_id")
								if api_id:
									self.api_key_id = self.utils.encrypt_data(api_id, passphrase)
									self.logger.create_log("API Key ID changed", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
							if "API Key" in options:
								api_secret = self.dialog.create_inputbox("Enter the API Key:", 8, 50, "api_secret")
								if api_secret:
									self.api_key = self.utils.encrypt_data(api_secret, passphrase)
									self.logger.create_log("API Key changed", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
				finally:
					user = None
					password = None
					api_id = None
					api_secret = None
					passphrase = None
					del user
					del password
					del api_id
					del api_secret
					del passphrase
		else:
			option = self.dialog.create_radiolist("Select a option:", 8, 55, OPTIONS_AUTHENTICATION_FALSE, "Authentication Method")
			if not option:
				return
			if option == "Enable":
				try:
					self.use_authentication = True
					passphrase = self.utils.get_passphrase(key_file)
					self.authentication_method = self.dialog.create_radiolist("Select a option:", 9, 55, AUTHENTICATION_METHOD_OPTIONS, "Authentication Method")
					if not self.authentication_method:
						return
					if self.authentication_method == "HTTP Authentication":
						user = self.dialog.create_inputbox("Enter username:", 8, 50, "http_user")
						password = self.dialog.create_passwordbox("Enter the password:", 8, 50, "password", True)
						if user and password:
							self.http_authentication_user = self.utils.encrypt_data(user, passphrase)
							self.http_authentication_password = self.utils.encrypt_data(password, passphrase)
					elif self.authentication_method == "API Key":
						api_id = self.dialog.create_inputbox("Enter the API Key ID:", 8, 50, "api_id")
						api_secret = self.dialog.create_inputbox("Enter the API Key:", 8, 50, "api_secret")
						if api_id and api_secret:
							self.api_key_id = self.utils.encrypt_data(api_id, passphrase)
							self.api_key = self.utils.encrypt_data(api_secret, passphrase)
					self.logger.create_log("Authentication method usage has been enabled", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
					self.logger.create_log(f"Authentication method: {self.authentication_method}", 3, "_modifyConfiguration", use_file_handler = True, file_name = log_file_name, user = user, group = group)
				finally:
					user = None
					password = None
					api_id = None
					api_secret = None
					passphrase = None
					del user
					del password
					del api_id
					del api_secret
					del passphrase


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
