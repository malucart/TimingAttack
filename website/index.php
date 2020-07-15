<?php
    require "header.php";
?>
    <main>
        <!-- Container which saves Ash and his talk -->
        <div class="container" style="margin-bottom: 50px;">
            <div class="row">
                <div class="col">
                    <!-- Copyright Nintendo -->
                    <i class="nes-ash"></i>
                </div>
                <div class="col-sm-9 col-xs-12">
                    <div class="nes-balloon from-left">
                        <p>Welcome to 8-bit Store <i class="nes-icon is-small heart"></i></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Second container which saves the description of the store and more -->
        <div class="container">
            <div class="row">
                <div class="col-xs-12 col-sm-12">
                    <div class="nes-container is-dark with-title">
                        <h3 class="title">About</h3>
                        <div>
                            <p>Join the best website to buy and sell any kind of video games everyday around the world.</p>
                        </div>
                    </div>
                </div>

                <!-- First square of three, and this one is the Sign Up -->
                <div class="col-xs-4 col-sm-4">
                    <div class="nes-container with-title is-centered" style="margin-top: 50px; margin-bottom: 50px;">
                        <h3 class="title">Let's start!</h3>
                        <i class="nes-icon star is-small"></i>
                        <a href="signup.php">Sign up</a>
                    </div>
                </div>

                <!-- Second square of three, and this one is the Login session -->
                <div class="col-xs-4 col-sm-4" style="margin-top: 40px;">
                    <div class="nes-container with-title is-centered">
                        <h3 class="title">Login</h3>
                        <div class="col-xs-6 col-sm-6 col-md-12">
                            <?php
                                // we just wanna see the log out form if the user is on the session
                                if (isset($_SESSION['userId'])) {
                                    echo '<form action="includes/logout.inc.php" method="post">
                                            <div>
                                                <label><button type="submit" name="logout-submit" class="nes-btn" style="margin-top: 15px;">Logout</button></label> <br />
                                            </div>
                                          </form>';
                                // if user is not in the session, then, let's see the login form
                                } else {
                                    echo '<form action="includes/login.inc.php" method="post">
                                            <div>
                                                <label>Username: </label><br />
                                                    <input text="text" name="mailuid" placeholder="username" required size="10" />
                                            </div>
                                            <div>
                                                <label>Password: </label><br />
                                                    <input type="password" name="pwd" placeholder="password" required size="10" />
                                            </div>
                                            <div>
                                                <label><button type="submit" name="login-submit" class="nes-btn" style="margin-top: 15px;">Login</button></label> <br />
                                            </div>
                                          </form>';
                                }
                            ?>
                        </div>
                    </div>
                </div>

                <!-- Third square of three, and this one is a section of stuffs the website would do, like "let's buy" and "let's sell" -->
                <div class="col-xs-4 col-sm-4" style="margin-top: 40px;">
                    <div class="nes-container with-title">
                        <h3 class="title">Go:</h3>
                        <ul>
                            <li><a href="">let's buy</a></li>
                            <li><a href="">let's sell</a></li>
                        </ul>
                    </div>
                </div>
    </main>

<?php
    require "footer.php";
?>