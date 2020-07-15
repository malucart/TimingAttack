<?php
    require "header.php";
?>
    <main>
            <!-- Sing Up -->
            <div class="container">
                <div class="col-xs-12 col-sm-12" style="margin-top: 40px;">
                    <div class="nes-container with-title is-centered" style="padding-left: 70px; padding-right: 70px; margin-right: 160px; margin-left: 160px;">
                        <h3 class="title">Sign Up</h3>
                        <form action="includes/signup.inc.php" method="post">
                            <label for="name_field" style="margin-top: 20px;">Username</label> <input type="text" name="uid" placeholder="Username" class="nes-input" />
                            <br />
                            <label for="name_field" style="margin-top: 20px;">Email</label> <input type="text" name="mail" placeholder="Email" class="nes-input" />
                            <br />
                            <label for="name_field" style="margin-top: 20px;">Password</label> <input type="password" name="pwd" placeholder="Password" class="nes-input" />
                            <br />
                            <label for="name_field" style="margin-top: 20px;">Repeat password</label> <input type="password" name="pwd-repeat" placeholder="Repeat Password" class="nes-input" />
                            <br />
                            <button type="submit" name="signup-submit" class="nes-btn is-success" style="margin-top: 20px;">Submit</button>
                        </form>
                    </div>
                </div>
    </main>

    <!-- footer -->
    <footer class="container">
                <div class="row">
                    <div class="col-xs-12" style="text-align: center;">
                        Copyright © 8-bit Store
                    </div>
                </div>
            </footer>
        </div>
    </body>
</html>