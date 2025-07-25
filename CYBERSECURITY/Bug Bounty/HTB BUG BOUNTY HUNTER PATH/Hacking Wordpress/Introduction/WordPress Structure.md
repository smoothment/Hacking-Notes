﻿## Default WordPress File Structure

WordPress can be installed on a Windows, Linux, or Mac OSX host. For this module, we will focus on a default WordPress installation on an Ubuntu Linux web server. WordPress requires a fully installed and configured LAMP stack (Linux operating system, Apache HTTP Server, MySQL database, and the PHP programming language) before installation on a Linux host. After installation, all WordPress supporting files and directories will be accessible in the webroot located at`/var/www/html`.

Below is the directory structure of a default WordPress install, showing the key files and subdirectories necessary for the website to function properly.

#### File Structure

```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html
.
â”â”€â”€ index.php
â”â”€â”€ license.txt
â”â”€â”€ readme.html
â”â”€â”€ wp-activate.php
â”â”€â”€ wp-admin
â”â”€â”€ wp-blog-header.php
â”â”€â”€ wp-comments-post.php
â”â”€â”€ wp-config.php
â”â”€â”€ wp-config-sample.php
â”â”€â”€ wp-content
â”â”€â”€ wp-cron.php
â”â”€â”€ wp-includes
â”â”€â”€ wp-links-opml.php
â”â”€â”€ wp-load.php
â”â”€â”€ wp-login.php
â”â”€â”€ wp-mail.php
â”â”€â”€ wp-settings.php
â”â”€â”€ wp-signup.php
â”â”€â”€ wp-trackback.php
â””â”€â”€ xmlrpc.php
```

---

## Key WordPress Files

The root directory of WordPress contains files that are needed to configure WordPress to function correctly.

- `index.php` is the homepage of WordPress.
 
- `license.txt` contains useful information such as the version WordPress installed.
 
- `wp-activate.php` is used for the email activation process when setting up a new WordPress site.
 
- `wp-admin` folder contains the login page for administrator access and the backend dashboard. Once a user has logged in, they can make changes to the site based on their assigned permissions. The login page can be located at one of the following paths:
 
 - `/wp-admin/login.php`
 - `/wp-admin/wp-login.php`
 - `/login.php`
 - `/wp-login.php`

This file can also be renamed to make it more challenging to find the login page.

- `xmlrpc.php` is a file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress [REST API](https://developer.wordpress.org/rest-api/reference).

---

## WordPress Configuration File

- The`wp-config.php` file contains information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.


```php
<?php
/** <SNIP> */
/** The name of the database for WordPress */
define( 'DB_NAME', 'database_name_here' );

/** MySQL database username */
define( 'DB_USER', 'username_here' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password_here' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Authentication Unique Keys and Salts */
/* <SNIP> */
define( 'AUTH_KEY', 'put your unique phrase here' );
define( 'SECURE_AUTH_KEY', 'put your unique phrase here' );
define( 'LOGGED_IN_KEY', 'put your unique phrase here' );
define( 'NONCE_KEY', 'put your unique phrase here' );
define( 'AUTH_SALT', 'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT', 'put your unique phrase here' );
define( 'NONCE_SALT', 'put your unique phrase here' );

/** WordPress Database Table prefix */
$table_prefix = 'wp_';

/** For developers: WordPress debugging mode. */
/** <SNIP> */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

---

## Key WordPress Directories

- The`wp-content` folder is the main directory where plugins and themes are stored. The subdirectory`uploads/` is usually where any files uploaded to the platform are stored. These directories and files should be carefully enumerated as they may lead to contain sensitive data that could lead to remote code execution or exploitation of other vulnerabilities or misconfigurations.

#### WP-Content


```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html/wp-content
.
â”â”€â”€ index.php
â”â”€â”€ plugins
â””â”€â”€ themes
```

- `wp-includes` contains everything except for the administrative components and the themes that belong to the website. This is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets.

#### WP-Includes

```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html/wp-includes
.
â”â”€â”€ <SNIP>
â”â”€â”€ theme.php
â”â”€â”€ update.php
â”â”€â”€ user.php
â”â”€â”€ vars.php
â”â”€â”€ version.php
â”â”€â”€ widgets
â”â”€â”€ widgets.php
â”â”€â”€ wlwmanifest.xml
â”â”€â”€ wp-db.php
â””â”€â”€ wp-diff.php
```
