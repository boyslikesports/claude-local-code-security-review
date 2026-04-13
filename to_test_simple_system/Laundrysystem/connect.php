<?php
$mysqli = new mysqli('127.0.0.1','xwn','111222333','bbn');
   if($mysqli->connect_errno){
      echo $mysqli->connect_errno.": ".$mysqli->connect_error;
   }
 ?>
