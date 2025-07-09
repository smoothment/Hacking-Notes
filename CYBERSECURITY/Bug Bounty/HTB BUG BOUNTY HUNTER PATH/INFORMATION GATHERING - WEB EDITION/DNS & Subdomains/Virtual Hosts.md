Once the DNS directs traffic to the correct server, the web server configuration becomes crucial in determining how the incoming requests are handled. Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.

## How Virtual Hosts Work: Understanding VHosts and Subdomains

At the core ofÂ `virtual hosting`Â is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address. This is achieved by leveraging theÂ `HTTP Host`Â header, a piece of information included in everyÂ `HTTP`Â request sent by a web browser.

The key difference betweenÂ `VHosts`Â andÂ `subdomains`Â is their relationship to theÂ `Domain Name System (DNS)`Â and the web server's configuration.

```ad-info
- `Subdomains`: These are extensions of a main domain name (e.g.,Â `blog.example.com`Â is a subdomain ofÂ `example.com`).Â `Subdomains`Â typically have their ownÂ `DNS records`, pointing to either the same IP address as the main domain or a different one. They can be used to organize different sections or services of a website.
- `Virtual Hosts`Â (`VHosts`): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g.,Â `example.com`) or subdomains (e.g.,Â `dev.example.com`). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.
```

If a virtual host does not have a DNS record, you can still access it by modifying theÂ `hosts`Â file on your local machine. TheÂ `hosts`Â file allows you to map a domain name to an IP address manually, bypassing DNS resolution.

Websites often have subdomains that are not public and won't appear in DNS records. TheseÂ `subdomains`Â are only accessible internally or through specific configurations.Â `VHost fuzzing`Â is a technique to discover public and non-publicÂ `subdomains`Â andÂ `VHosts`Â by testing various hostnames against a known IP address.

Virtual hosts can also be configured to use different domains, not just subdomains. For example:


```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

Here,Â `example1.com`,Â `example2.org`, andÂ `another-example.net`Â are distinct domains hosted on the same server. The web server uses theÂ `Host`Â header to serve the appropriate content based on the requested domain name.

### Server VHost Lookup

The following illustrates the process of how a web server determines the correct content to serve based on theÂ `Host`Â header:

![](https://mermaid.ink/svg/pako:eNqNUsFuwjAM_ZUop00CPqAHDhubuCBNBW2XXrzUtNFap3McOoT496WUVUA3aTkltp_f84sP2rgcdaI9fgYkgwsLBUOdkYqnARZrbAMk6oFd65HHiTd8XyPvfku9WpYA1dJ5eXS0tcW4ZOFMqJEkdU4y6vNnqul8PvRO1HKzeVFpp9KLumvbdmapAsItoy1KmRlX3_fwAXTd4OkLakuoOjVqiZAj_7_PaJJEPVvK1QrElJYK1UcDg1h3HmOEmV4LSlEC0-CA6i24Zb406IRhizuM7BV6BVFCit4FNuh77GX9DeGfmEu-s_mD4b5x5PH2Y4aqhfVNBftufomsGemJrpFrsHncqkOHy7SUWGOmk3jNgT8yndEx1kEQt96T0YlwwIlmF4pSJ1uofHyFJgf52cchirkVx6t-aU-7e_wG--_4bQ)


```ad-important
1. `Browser Requests a Website`: When you enter a domain name (e.g.,Â `www.inlanefreight.com`) into your browser, it initiates an HTTP request to the web server associated with that domain's IP address.
2. `Host Header Reveals the Domain`: The browser includes the domain name in the request'sÂ `Host`Â header, which acts as a label to inform the web server which website is being requested.
3. `Web Server Determines the Virtual Host`: The web server receives the request, examines theÂ `Host`Â header, and consults its virtual host configuration to find a matching entry for the requested domain name.
4. `Serving the Right Content`: Upon identifying the correct virtual host configuration, the web server retrieves the corresponding files and resources associated with that website from its document root and sends them back to the browser as the HTTP response.
```

In essence, theÂ `Host`Â header functions as a switch, enabling the web server to dynamically determine which website to serve based on the domain name requested by the browser.

### Types of Virtual Hosting

There are three primary types of virtual hosting, each with its advantages and drawbacks:

```ad-info
1. `Name-Based Virtual Hosting`: This method relies solely on theÂ `HTTP Host header`Â to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses. Itâ€™s cost-effective, easy to set up, and supports most modern web servers. However, it requires the web server to support name-basedÂ `virtual hosting`Â and can have limitations with certain protocols likeÂ `SSL/TLS`.
2. `IP-Based Virtual Hosting`: This type of hosting assigns a unique IP address to each website hosted on the server. The server determines which website to serve based on the IP address to which the request was sent. It doesn't rely on theÂ `Host header`, can be used with any protocol, and offers better isolation between websites. Still, it requires multiple IP addresses, which can be expensive and less scalable.
3. `Port-Based Virtual Hosting`: Different websites are associated with different ports on the same IP address. For example, one website might be accessible on port 80, while another is on port 8080.Â `Port-based virtual hosting`Â can be used when IP addresses are limited, but itâ€™s not as common or user-friendly asÂ `name-based virtual hosting`Â and might require users to specify the port number in the URL.
```

## Virtual Host Discovery Tools

While manual analysis ofÂ `HTTP headers`Â and reverseÂ `DNS lookups`Â can be effective, specializedÂ `virtual host discovery tools`Â automate and streamline the process, making it more efficient and comprehensive. These tools employ various techniques to probe the target server and uncover potentialÂ `virtual hosts`.

Several tools are available to aid in the discovery of virtual hosts:

| Tool                                                 | Description                                                                                                      | Features                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.                  | Supports recursion, wildcard discovery, and various filters.    |
| [ffuf](https://github.com/ffuf/ffuf)                 | Another fast web fuzzer that can be used for virtual host discovery by fuzzing theÂ `Host`Â header.                | Customizable wordlist input and filtering options.              |
|                                                      |                                                                                                                  |                                                                 |

### gobuster

Gobuster is a versatile tool commonly used for directory and file brute-forcing, but it also excels at virtual host discovery. It systematically sends HTTP requests with differentÂ `Host`Â headers to a target IP address and then analyses the responses to identify valid virtual hosts.

There are a couple of things you need to prepare to brute forceÂ `Host`Â headers:

1. `Target Identification`: First, identify the target web server's IP address. This can be done through DNS lookups or other reconnaissance techniques.
2. `Wordlist Preparation`: Prepare a wordlist containing potential virtual host names. You can use a pre-compiled wordlist, such as SecLists, or create a custom one based on your target's industry, naming conventions, or other relevant information.

TheÂ `gobuster`Â command to bruteforce vhosts generally looks like this:


```shell-session
smoothment@htb[/htb]$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

```ad-summary
- TheÂ `-u`Â flag specifies the target URL (replaceÂ `<target_IP_address>`Â with the actual IP).
- TheÂ `-w`Â flag specifies the wordlist file (replaceÂ `<wordlist_file>`Â with the path to your wordlist).
- TheÂ `--append-domain`Â flag appends the base domain to each word in the wordlist.
```

In newer versions of Gobuster, the `--append-domain` flag is required to append the base domain to each word in the wordlist when performing virtual host discovery. This flag ensures that Gobuster correctly constructs the full virtual hostnames, which is essential for the accurate enumeration of potential subdomains. In older versions of Gobuster, this functionality was handled differently, and the --append-domain flag was not necessary. Users of older versions might not find this flag available or needed, as the tool appended the base domain by default or employed a different mechanism for virtual host generation.

`Gobuster`Â will output potential virtual hosts as it discovers them. Analyze the results carefully, noting any unusual or interesting findings. Further investigation might be needed to confirm the existence and functionality of the discovered virtual hosts.

There are a couple of other arguments that are worth knowing:

```ad-important
- Consider using theÂ `-t`Â flag to increase the number of threads for faster scanning.
- TheÂ `-k`Â flag can ignore SSL/TLS certificate errors.
- You can use theÂ `-o`Â flag to save the output to a file for later analysis.
```



```shell-session
smoothment@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:81
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.inlanefreight.htb:81 Status: 200 [Size: 100]
[...]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```


# Questions
----

![Pasted image 20250128123138.png](../../../../IMAGES/Pasted%20image%2020250128123138.png)


```ad-hint
To begin with, let's edit our `/etc/hosts` file in the following way:

`echo '83.136.249.42 inlanefreight.htb' | sudo tee -a /etc/hosts`

Now we can perform the following:

`gobuster vhost -u http://inlanefreight.htb:45825 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100`
```


Now let's wait until scan is done and we'll see the following:

```
gobuster vhost -u http://inlanefreight.htb:45825 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:45825
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: blog.inlanefreight.htb:45825 Status: 200 [Size: 98]
Found: support.inlanefreight.htb:45825 Status: 200 [Size: 104]
Found: forum.inlanefreight.htb:45825 Status: 200 [Size: 100]
Found: admin.inlanefreight.htb:45825 Status: 200 [Size: 100]
Found: vm5.inlanefreight.htb:45825 Status: 200 [Size: 96]
Found: browse.inlanefreight.htb:45825 Status: 200 [Size: 102]
Found: web17611.inlanefreight.htb:45825 Status: 200 [Size: 106]
```

![Pasted image 20250128123828.png](../../../../IMAGES/Pasted%20image%2020250128123828.png)


We got all of the answers, they would be the following:

![Pasted image 20250128123910.png](../../../../IMAGES/Pasted%20image%2020250128123910.png)

