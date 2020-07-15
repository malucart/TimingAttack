<?php

// creating server: server name, username, password, and database name 
$servername = "localhost";
$dBUsername = "root";
$dBPassword = "";
$dBName = "webserverdb";

// conection with the server 
$conn = mysqli_connect($servername, $dBUsername, $dBPassword, $dBName);

// if doesnt have conection the user will know
if (!$conn) {
    die("Connection failed: ".mysqli_connect_error());
}

?>