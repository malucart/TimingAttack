<html>
<head>
    <title>Log In</title>
    <style>
    .error {color: #FF0000;}
    </style>
</head>
<body>

  <?php
    // Initialize the session
    session_start();
    echo "session started ";

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
      if (check($_POST["username"], "test")) {
        sleep(0.005);
        echo "username correct! ";
        if (check($_POST["password"], "12345")) {
          echo "password correct! ";
        }
        else {
          echo "password incorrect! ";
        }
      }
      else {
        echo "username incorrect! ";
      }

    }


    function check($userInput, $trueValue) {
      if (hash(md5, $userInput) == hash(md5, $trueValue)) {
        return true;
      }
      return false;
    }

  ?>


  <div id="container" style="font-family:sans-serif; padding: 1em">
    <div style="font-size: 2em; text-align: center; padding: 1em">Log In</div>
    <form method="post" action="loginTest.php">

    <div style="text-align: center; padding: 1em">
      <input type="text" name="username" placeholder="Username*" class="text-input">
    </div>

    <div style="text-align: center; padding: 1em">
      <input type="text" name="password" placeholder="Password*" class="text-input">
    </div>

    <div style="text-align: center; padding: 1em">
      <input type="submit" name="submit" class="button-input">
    </div>
  </div>

</body>
