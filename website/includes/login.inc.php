<?php

// isset() --> method that include stuffs. So, it's going to include what the user posted on Login section
if (isset($_POST['login-submit'])) {
    // require a php file that makes conection with the database
    require 'dbh.inc.php';

    // info from user is now saved in variables into the database
    $mailuid = $_POST['mailuid'];
    $password = $_POST['pwd'];

    // error message if username/email or password is empty
    if (empty($mailuid) || empty($password)) {
        header("Location: ../index.php?error=emptyfields");
        exit();
    } else {
        $sql = "SELECT * FROM users WHERE uidUsers=?;";
        // conection initialized
        $stmt = mysqli_stmt_init($conn);
        // if something fails
        if (!mysqli_stmt_prepare($stmt, $sql)) {
            header("Location: ../index.php?error=sqlerror");
            exit();
        // if it doesnt fail and everything is ok
        } else {
            // what kind of data we want to send into the database. In this case, one string (username or email)
            mysqli_stmt_bind_param($stmt, "s", $mailuid);
            mysqli_stmt_execute($stmt);

            // the result from the database is going to be save in this variable $result
            $result = mysqli_stmt_get_result($stmt);
            // fetches a result row as an associative array, so in this case, $result has data
            if ($row = mysqli_fetch_assoc($result)) {
                // checkes if the hashed password matched with what we have on the database
                $pwdCheck = password_verify($password, $row['pwdUsers']);
                if ($pwdCheck == false) {
                    header("Location: ../index.php?error=wrongpwd");
                    exit();
                } else if ($pwdCheck == true) {
                    session_start();
                    $_SESSION['userId'] = $row['idUsers'];
                    $_SESSION['userUid'] = $row['uidUsers'];

                    header("Location: ../index.php?login=success");
                    exit();
                } else {
                    header("Location: ../index.php?error=wrongpwd");
                    exit();
                }
            // for this case, $result doesnt have any data
            } else {
                header("Location: ../index.php?error=nouser"); // because there is no user or email that matches with what we have on the database
                exit();
            }
        }
    }

// if the user is here without post anything in Login section
} else {
    header("Location: ../index.php");
    exit();
}

?>
