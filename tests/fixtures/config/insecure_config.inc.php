;
; INSECURE OJS configuration (no exit guard line on purpose).
;
[general]
installed = On
base_url = "http://journal.example.org"
session_cookie_httponly = Off
session_samesite = None
allowed_hosts = "*"
disable_path_info = Off

[security]
force_ssl = Off
salt = "changeme"
api_key_secret = ""

[database]
driver = mysqli
host = localhost
username = ojs
password = password
name = ojs

[files]
files_dir = files

[debug]
show_stacktrace = On
