<?php
    require "header.php";
?>

<main>
     <!-- Shows the user is logged in or logged out -->
     <div class="container" style="margin-bottom: 50px;">
            <div class="row">
                <div class="col-xs-12 col-sm-12">
                    <?php 
                        // if the session has the user, so the user is logged in
                        if (isset($_SESSION['userId'])) {
                            echo '<div class="nes-container is-rounded"><p style="text-align:center;">You are logged in!.</p></div>';
                        // if the session hasn't the user, so the user is logged out
                        } else {
                            echo '<div class="nes-container is-rounded is-dark"><p style="text-align:center;">You are logged out..</p></div>';
                        }
                    ?>
                </div>
            </div>
        </div>
</main>