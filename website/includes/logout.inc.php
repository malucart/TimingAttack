<?php

    //start session
    session_start();
    // delete values in the variables
    session_unset();
    // destroys the session running in the current website
    session_destroy();
    header("Location: ../index.php");
?>