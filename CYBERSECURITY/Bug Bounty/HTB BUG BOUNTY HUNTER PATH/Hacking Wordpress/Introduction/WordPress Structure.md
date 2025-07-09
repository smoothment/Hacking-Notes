## Default WordPress File Structure

WordPress can be installed on a Windows, Linux, or Mac OSX host. For this module, we will focus on a default WordPress installation on an Ubuntu Linux web server. WordPress requires a fully installed and configured LAMP stack (Linux operating system, Apache HTTP Server, MySQL database, and the PHP programming language) before installation on a Linux host. After installation, all WordPress supporting files and directories will be accessible in the webroot located atÂ `/var/www/html`.

Below is the directory structure of a default WordPress install, showing the key files and subdirectories necessary for the website to function properly.

#### File Structure

```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html
.
â”œâ”€â”€ index.php
â”œâ”€â”€ license.txt
â”œâ”€â”€ readme.html
â”œâ”€â”€ wp-activate.php
â”œâ”€â”€ wp-admin
â”œâ”€â”€ wp-blog-header.php
â”œâ”€â”€ wp-comments-post.php
â”œâ”€â”€ wp-config.php
â”œâ”€â”€ wp-config-sample.php
â”œâ”€â”€ wp-content
â”œâ”€â”€ wp-cron.php
â”œâ”€â”€ wp-includes
â”œâ”€â”€ wp-links-opml.php
â”œâ”€â”€ wp-load.php
â”œâ”€â”€ wp-login.php
â”œâ”€â”€ wp-mail.php
â”œâ”€â”€ wp-settings.php
â”œâ”€â”€ wp-signup.php
â”œâ”€â”€ wp-trackback.php
â””â”€â”€ xmlrpc.php
```

---

## Key WordPress Files

The root directory of WordPress contains files that are needed to configure WordPress to function correctly.

- `index.php`Â is the homepage of WordPress.
    
- `license.txt`Â contains useful information such as the version WordPress installed.
    
- `wp-activate.php`Â is used for the email activation process when setting up a new WordPress site.
    
- `wp-admin`Â folder contains the login page for administrator access and the backend dashboard. Once a user has logged in, they can make changes to the site based on their assigned permissions. The login page can be located at one of the following paths:
    
    - `/wp-admin/login.php`
    - `/wp-admin/wp-login.php`
    - `/login.php`
    - `/wp-login.php`

This file can also be renamed to make it more challenging to find the login page.

- `xmlrpc.php`Â is a file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPressÂ [REST API](https://developer.wordpress.org/rest-api/reference).

---

## WordPress Configuration File

- TheÂ `wp-config.php`Â file contains information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.


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
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

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

- TheÂ `wp-content`Â folder is the main directory where plugins and themes are stored. The subdirectoryÂ `uploads/`Â is usually where any files uploaded to the platform are stored. These directories and files should be carefully enumerated as they may lead to contain sensitive data that could lead to remote code execution or exploitation of other vulnerabilities or misconfigurations.

#### WP-Content


```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html/wp-content
.
â”œâ”€â”€ index.php
â”œâ”€â”€ plugins
â””â”€â”€ themes
```

- `wp-includes`Â contains everything except for the administrative components and the themes that belong to the website. This is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets.

#### WP-Includes

```shell-session
smoothment@htb[/htb]$ tree -L 1 /var/www/html/wp-includes
.
â”œâ”€â”€ <SNIP>
â”œâ”€â”€ theme.php
â”œâ”€â”€ update.php
â”œâ”€â”€ user.php
â”œâ”€â”€ vars.php
â”œâ”€â”€ version.php
â”œâ”€â”€ widgets
â”œâ”€â”€ widgets.php
â”œâ”€â”€ wlwmanifest.xml
â”œâ”€â”€ wp-db.php
â””â”€â”€ wp-diff.php
```
