;<?php exit; ?>
; Do not edit/delete the above line!
;
[general]
installed = On
base_url = "https://journal.example.org"
session_cookie_httponly = On
session_samesite = Lax
allowed_hosts = '["journal.example.org"]'
disable_path_info = On
trust_x_forwarded_for = Off
allow_url_fopen = Off
session_lifetime = 3600
sandbox = Off
user_validation_period = 14

[security]
force_ssl = On
force_login_ssl = On
session_check_ip = On
encryption = sha1
session_expire_on_close = On
salt = "Xk92Lm!pQz7vR3wEa1Tn8Yb4Uc6Gd0HfJsKlMnOpQr2St5"
api_key_secret = "aB3dE6gH9jK2mN5pQ8sT1vW4xZ7cF0iLpRtUwYbDgKnQ"
reset_seconds = 3600
allow_plugin_install = gallery_only
password_timeout = 15
cipher = aes-256-gcm
cookie_encryption = On
app_key = "aB3dE6gH9jK2mN5pQ8sT1vW4xZ7cF0iLpRtUwYbDgKnQ"
allowed_html = ""

[database]
driver = mysqli
host = localhost
username = ojs_prod_user
password = "9f8Xc!2mQ7zR-vK4wPnD3sLg"
name = ojs_production
debug = Off
secure = On

[files]
files_dir = /var/lib/ojs/files
umask = 0027
public_user_dir_size = 3000

[email]
smtp_suppress_cert_check = Off
require_validation = On

[captcha]
altcha = On

[debug]
show_stacktrace = Off
display_errors = Off
deprecation_warnings = Off
log_web_service_info = Off
