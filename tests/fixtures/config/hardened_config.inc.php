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

[security]
force_ssl = On
salt = "Xk92Lm!pQz7vR3wEa1Tn8Yb4Uc6Gd0HfJsKlMnOpQr2St5"
api_key_secret = "aB3dE6gH9jK2mN5pQ8sT1vW4xZ7cF0iLpRtUwYbDgKnQ"

[database]
driver = mysqli
host = localhost
username = ojs_prod_user
password = "9f8Xc!2mQ7zR-vK4wPnD3sLg"
name = ojs_production

[files]
files_dir = /var/lib/ojs/files

[debug]
show_stacktrace = Off
