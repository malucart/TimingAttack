    <main>

    <!-- Everything necessary to make the website pretty (framework and personal css) with a mobile style as well-->
        <head>
            <meta name=viewport content="width=device-width, initial-scale=1">
            <meta charset="UTF-8">
            <!-- This step works on mobile -->
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="ie=edge">
            <title>Login</title>
            <!-- latest update from nes.css -->
            <link href="https://unpkg.com/nes.css@latest/css/nes.min.css" rel="stylesheet" />
            <link href="https://fonts.googleapis.com/css?family=Press+Start+2P" rel="stylesheet">
            <!-- flexbox grid -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flexboxgrid/6.3.1/flexboxgrid.min.css" type="text/css">
            <!-- my css -->
            <link href="css/style.css" rel="stylesheet" />
            <title></title>
        </head>

        <body>

            <!-- First parte, which is the store's name and social media links -->
            <header>
                <nav class="header">
                    <div class="container">
                        <h2>
                            <a class="snes-logo" href=""></a>
                            8-bit Store
                            <a href="#" style="float: right; margin-left: 20px;">
                                <i class="nes-icon twitter"></i>
                            </a>
                            <a href="#" style="float: right; margin-left: 20px;">
                                <i class="nes-icon instagram"></i>
                            </a>
                            <a href="#" style="float: right;">
                                <i class="nes-icon facebook"></i>
                            </a>
                        </h2>
                    </div>
                </nav>
            </header>

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