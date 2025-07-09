So far, we have only been using IDOR vulnerabilities to access files and resources that are out of our user's access. However, IDOR vulnerabilities may also exist in function calls and APIs, and exploiting them would allow us to perform various actions as other users.

WhileÂ `IDOR Information Disclosure Vulnerabilities`Â allow us to read various types of resources,Â `IDOR Insecure Function Calls`Â enable us to call APIs or execute functions as another user. Such functions and APIs can be used to change another user's private information, reset another user's password, or even buy items using another user's payment information. In many cases, we may be obtaining certain information through an information disclosure IDOR vulnerability and then using this information with IDOR insecure function call vulnerabilities, as we will see later in the module.

---

## Identifying Insecure APIs

Going back to ourÂ `Employee Manager`Â web application, we can start testing theÂ `Edit Profile`Â page for IDOR vulnerabilities:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg)

When we click on theÂ `Edit Profile`Â button, we are taken to a page to edit information of our user profile, namelyÂ `Full Name`,Â `Email`, andÂ `About Me`, which is a common feature in many web applications:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_edit_profile.jpg)

We can change any of the details in our profile and clickÂ `Update profile`, and we'll see that they get updated and persist through refreshes, which means they get updated in a database somewhere. Let's intercept theÂ `Update`Â request in Burp and look at it:

![update_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_update_request.jpg)

We see that the page is sending aÂ `PUT`Â request to theÂ `/profile/api.php/profile/1`Â API endpoint.Â `PUT`Â requests are usually used in APIs to update item details, whileÂ `POST`Â is used to create new items,Â `DELETE`Â to delete items, andÂ `GET`Â to retrieve item details. So, aÂ `PUT`Â request for theÂ `Update profile`Â function is expected. The interesting bit is the JSON parameters it is sending:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

We see that theÂ `PUT`Â request includes a few hidden parameters, likeÂ `uid`,Â `uuid`, and most interestinglyÂ `role`, which is set toÂ `employee`. The web application also appears to be setting the user access privileges (e.g.Â `role`) on the client-side, in the form of ourÂ `Cookie: role=employee`Â cookie, which appears to reflect theÂ `role`Â specified for our user. This is a common security issue. The access control privileges are sent as part of the client's HTTP request, either as a cookie or as part of the JSON request, leaving it under the client's control, which could be manipulated to gain more privileges.

So, unless the web application has a solid access control system on the back-end,Â `we should be able to set an arbitrary role for our user, which may grant us more privileges`. However, how would we know what other roles exist?

---

## Exploiting Insecure APIs

We know that we can change theÂ `full_name`,Â `email`, andÂ `about`Â parameters, as these are the ones under our control in the HTML form in theÂ `/profile`Â web page. So, let's try to manipulate the other parameters.

There are a few things we could try in this case:

1. Change ourÂ `uid`Â to another user'sÂ `uid`, such that we can take over their accounts
2. Change another user's details, which may allow us to perform several web attacks
3. Create new users with arbitrary details, or delete existing users
4. Change our role to a more privileged role (e.g.Â `admin`) to be able to perform more actions

Let's start by changing ourÂ `uid`Â to another user'sÂ `uid`Â (e.g.Â `"uid": 2`). However, any number we set other than our ownÂ `uid`Â gets us a response ofÂ `uid mismatch`:

![uid_mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uid_mismatch.jpg)

The web application appears to be comparing the request'sÂ `uid`Â to the API endpoint (`/1`). This means that a form of access control on the back-end prevents us from arbitrarily changing some JSON parameters, which might be necessary to prevent the web application from crashing or returning errors.

Perhaps we can try changing another user's details. We'll change the API endpoint toÂ `/profile/api.php/profile/2`, and changeÂ `"uid": 2`Â to avoid the previousÂ `uid mismatch`:

![uuid_mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uuid_mismatch.jpg)

As we can see, this time, we get an error message sayingÂ `uuid mismatch`. The web application appears to be checking if theÂ `uuid`Â value we are sending matches the user'sÂ `uuid`. Since we are sending our ownÂ `uuid`, our request is failing. This appears to be another form of access control to prevent users from changing another user's details.

Next, let's see if we can create a new user with aÂ `POST`Â request to the API endpoint. We can change the request method toÂ `POST`, change theÂ `uid`Â to a newÂ `uid`, and send the request to the API endpoint of the newÂ `uid`:

![create_new_user_1](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_1.jpg)

We get an error message sayingÂ `Creating new employees is for admins only`. The same thing happens when we send aÂ `Delete`Â request, as we getÂ `Deleting employees is for admins only`. The web application might be checking our authorization through theÂ `role=employee`Â cookie because this appears to be the only form of authorization in the HTTP request.

Finally, let's try to change ourÂ `role`Â toÂ `admin`/`administrator`Â to gain higher privileges. Unfortunately, without knowing a validÂ `role`Â name, we getÂ `Invalid role`Â in the HTTP response, and ourÂ `role`Â does not update:Â 

![invalid_role](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_invalid_role.jpg)

So,Â `all of our attempts appear to have failed`. We cannot create or delete users as we cannot change ourÂ `role`. We cannot change our ownÂ `uid`, as there are preventive measures on the back-end that we cannot control, nor can we change another user's details for the same reason.Â `So, is the web application secure against IDOR attacks?`.

So far, we have only been testing theÂ `IDOR Insecure Function Calls`. However, we have not tested the API'sÂ `GET`Â request forÂ `IDOR Information Disclosure Vulnerabilities`. If there was no robust access control system in place, we might be able to read other users' details, which may help us with the previous attacks we attempted.

`Try to test the API against IDOR Information Disclosure vulnerabilities by attempting to get other users' details with GET requests`. If the API is vulnerable, we may be able to leak other users' details and then use this information to complete our IDOR attacks on the function calls.

# Question
---

![Pasted image 20250217161733.png](../../../../IMAGES/Pasted%20image%2020250217161733.png)

We can check the following request:

```
PUT /profile/api.php/profile/1 HTTP/1.1

Host: 94.237.48.103:48289

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: http://94.237.48.103:48289/profile/index.php

Content-type: application/json

Content-Length: 208

Origin: http://94.237.48.103:48289

Connection: keep-alive

Cookie: role=employee

Priority: u=0



{"uid":1,"uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"employee","full_name":"Amy Lindon","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```

Once we try to upload our profile, we get this request, it is a `PUT` request, so, let's try changing the value in the following way:

```
GET /profile/api.php/profile/5 HTTP/1.1

Host: 94.237.48.103:48289

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: http://94.237.48.103:48289/profile/index.php

Content-type: application/json

Content-Length: 208

Origin: http://94.237.48.103:48289

Connection: keep-alive

Cookie: role=employee

Priority: u=0



{"uid":5,"uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"employee","full_name":"Amy Lindon","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```

If we do so, we get the following:

```
HTTP/1.1 200 OK

Date: Mon, 17 Feb 2025 21:18:35 GMT

Server: Apache/2.4.41 (Ubuntu)

Vary: Accept-Encoding

Content-Length: 177

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html; charset=UTF-8



{"uid":"5","uuid":"eb4fe264c10eb7a528b047aa983a4829","role":"employee","full_name":"Callahan Woodhams","email":"c_woodhams@employees.htb","about":"I don't like quoting others!"}
```

Answer is:

```
eb4fe264c10eb7a528b047aa983a4829
```
