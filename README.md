# Argument Injection Hammer

Argument Injection Hammer is an extension for the intercepting proxy [Burp Suite](https://portswigger.net/burp/) that extends the scanner's ability to detect argument injection and manipulation vulnerabilities in web applications and web services.

A web application is vulnerable to [argument injection](https://cwe.mitre.org/data/definitions/88.html) when untrusted inputs are passed as arguments to an external command.  An attacker can manipulate the arguments passed to the process to trigger either an arbitrary file write, arbitrary file read, or OS command injection depending on the supported arguments of the command and how the command is executed.  Argument injection should not be confused with [OS command injection](https://cwe.mitre.org/data/definitions/78.html) in which it is possible to use shell metacharacters to force the target application to execute additional arbitrary OS commands.

The extension contains payloads that can detect argument injection and manipulation vulnerabilities associated with common Linux commands using both in-band detection techniques and timing-based detection techniques.  The extension also supports limited brute forcing of short argument flags. 

## Supported Command Payloads

* `awk` 
* `curl`
* `date`
* `find`
* `git`
* `jrunscript`
* `lua`
* `mysql`
* `nmap`
* `openssl`
* `perl`
* `php`
* `php-cgi`
* `python`
* `readelf`
* `ruby`
* `sed`
* `sendmail`
* `sort`
* `sqlite3`
* `ssh`
* `tar`
* `wget`
* `zip`

## Installation

This extension is written in Python, so make sure to [configure Jython first within Burp Suite](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).  After configuring Jython, simply add the extension into Burp Suite (Extender -> Extensions -> Add).

## Future Ideas

* Support out-of-band detection techniques.
* Add payloads to target common Windows commands.
* Add payloads for additional Linux commands.