---
sticker: lucide//code
---
Once we accessed the page underÂ `/blog`, we got a message sayingÂ `Admin panel moved to academy.htb`. If we visit the website in our browser, we getÂ `canâ€™t connect to the server at www.academy.htb`:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/54/web_fnb_cant_connect_academy.jpg)

This is because the exercises we do are not public websites that can be accessed by anyone but local websites within HTB. Browsers only understand how to go to IPs, and if we provide them with a URL, they try to map the URL to an IP by looking into the localÂ `/etc/hosts`Â file and the public DNSÂ `Domain Name System`. If the URL is not in either, it would not know how to connect to it.

If we visit the IP directly, the browser goes to that IP directly and knows how to connect to it. But in this case, we tell it to go toÂ `academy.htb`, so it looks into the localÂ `/etc/hosts`Â file and doesn't find any mention of it. It asks the public DNS about it (such as Google's DNSÂ `8.8.8.8`) and does not find any mention of it, since it is not a public website, and eventually fails to connect. So, to connect toÂ `academy.htb`, we would have to add it to ourÂ `/etc/hosts`Â file. We can achieve that with the following command:


```shell-session
smoothment@htb[/htb]$ sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

Now we can visit the website (don't forget to add the PORT in the URL) and see that we can reach the website:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/54/web_fnb_main_site.jpg)

However, we get the same website we got when we visit the IP directly, soÂ `academy.htb`Â is the same domain we have been testing so far. We can verify that by visitingÂ `/blog/index.php`, and see that we can access the page.

When we run our tests on this IP, we did not find anything aboutÂ `admin`Â or panels, even when we did a fullÂ `recursive`Â scan on our target.Â `So, in this case, we start looking for sub-domains under '*.academy.htb' and see if we find anything, which is what we will attempt in the next section.`
