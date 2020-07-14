<?php
// asset() --> method used to include stuffs, so, in this case, it will include what the user posted in Sign Up section
if (isset($_POST['signup-submit'])) {

    // require a php file that makes conection with the database
    require 'dbh.inc.php';

    // info from user is now saved in variables into the database
    $username = $_POST['uid'];
    $email = $_POST['mail'];
    $password = $_POST['pwd'];
    $passwordRepeat = $_POST['pwd-repeat'];

    // if any info is missing, it will send us a error
    if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
        // this is what is going to appear in the link 
        header("Location: ../signup.php?error=emptyfields&uid=".$username."&mail=".$email);
        // exit() --> it's going to stop the script from running 
        exit();
    // filter_var() --> gets two values, one that was submitted and another one to show what we are going to do with the value submitted (in this case, checks it's a valid email)
    // ps: I will explain "preg_match()" below
    // so, this statement means: if the email is not valid and it's a crazy one, the link will show up "invalid email"
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL) && !preg_match("/^[a-zA-Z0-9]*$/", $username)) {
        header("Location: ../signup.php?error=invalidmailuid");
        exit();
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header("Location: ../signup.php?error=invalidmail&uid=".$username);
        exit();
    // preg_match() --> method that checks if something is inside of something else.
    // for example, if I have $string = "I love playing guitar", then, I use preg_math(/guitar/, $string)
    // it will checks if "guitar" makes part of $string
    // In this case, if username doesnt have any value like a-zA-Z0-9, so it's going to send us a error on the link
    } else if (!preg_match("/^[a-zA-Z0-9]*$/", $username)) {
        header("Location: ../signup.php?error=invaliduid&mail=".$email);
        exit();
    // if the two passwords don't match each other
    } else if ($password !== $passwordRepeat) {
        header("Location: ../signup.php?error=passwordcheck&uid=".$username."&mail=".$email);
        exit();
    // username already taken into the database 
    } else {
        $sql = "SELECT uidUsers FROM users WHERE uidUsers=?";
        // conection initialized 
        $stmt = mysqli_stmt_init($conn);
        // if it does fail, it's going to show up a sql error message
        if (!mysqli_stmt_prepare($stmt, $sql)) {
            header("Location: ../signup.php?error=sqlerror");
            exit();
        // if there is no fail
        } else {
            // it's going to take the info from the user and send it into the database
            // "s" --> string
            // for example, if we would have multiple parameters we could use "ss" and put $username, $password
            // but in this case it's just one string parameter which will be $username
            mysqli_stmt_bind_param($stmt, "s", $username);
            // now, it runs the info on the database
            mysqli_stmt_execute($stmt);
            // stores the result from the database in $stmt
            mysqli_stmt_store_result($stmt);
            // when we gets info from the database, we got it in rows, so if we will stores a number of rows of $stmt into the $resultCheck
            $resultCheck = mysqli_stmt_num_rows($stmt);
            // if $resultCheck is greater than zero, then it's going to show up a message on the link about user already had been taken
            if ($resultCheck > 0) {
                header("Location: ../signup.php?error=usertaken&mail=".$email);
                exit();
            // finally, the moment with no error for the user!
            } else {
                // all of these (uidUsers, emailUsers, pwdUsers) were created in my database, so that's why i'm using them
                // in "VALUES" we're going to use placeholders
                $sql = "INSERT INTO users(uidUsers, emailUsers, pwdUsers) VALUES (?, ?, ?)";
                // runs inside the database
                $stmt = mysqli_stmt_init($conn);
                // if these info doesnt run on database, it sends us a error
                if (!mysqli_stmt_prepare($stmt, $sql)) {
                    header("Location: ../signup.php?error=sqlerror");
                    exit();
                } else {
                    $hashedPwd = password_hash($password, PASSWORD_DEFAULT);
                    // If I dont wanna a hashed password, consequently, I should change "$hashedPwd" to "$password"
                    mysqli_stmt_bind_param($stmt, "sss", $username, $email, $hashedPwd);
                    mysqli_stmt_execute($stmt);
                    header("Location: ../signup.php?signup=sucess");
                    exit();
                }
            }
        }
    }
    // close conection with database
    mysqli_stmt_close($stmt);
    mysqli_close($conn);
// here is just if the user appears without post anything
} else {
    header("Location: ../signup.php");
    exit();
}