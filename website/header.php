<?php
    session_start();
?>
<!DOCTYPE html>
<html>
    <!-- Everything necessary to make the website pretty (framework and personal css) with a mobile style as well-->
    <head>
        <meta name=viewport content="width=device-width, initial-scale=1">
        <meta charset="UTF-8">
        <!-- This step works on mobile -->
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <title>8-bit Store</title>
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
                        <a class="snes-logo"></a>
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

        