![Pasted image 20241216212137.png](../../IMAGES/Pasted%20image%2020241216212137.png)

Another day, another challenge and, unfortunately for McSkidy, another intrusion in their Azure tenant. Before joining McSkidy in her investigation, there's some catching up to do, and this is a story best told in rhyme: 

```
_As SOC-mas approached, so did the need,_

_To provide those without, with something to read._

_Care4Wares tried, they made it their mission,_

_A gift for all wares, a SOC-mas tradition._

_

 

McSkidy logged on and felt some confusion,

An alert saying here, a detected intrusion.

Inspection began as to what was at fault,

It seems access was gained to McSkidys key vault.

 

She checked and she checked as she had to be sure,

But it hadnâ€™t been long since adopting Azure.

Troubleshooting ensued, ideas had been tabled,

Which would have been great, if logs were enabled.

 

With three hours slept,

And no records kept.

McSkidy then knew,

What she needed to do.

 

Itâ€™s true that on her, this town does depend,

But to find what was wrong, she needed a friend.

So clearing her throat and preparing her pitch,

She picked up her phone and called up the Glitch.

_

```


It was late. Too late. McSkidy's eyelids felt as though they had dumbbells attached to them. The sun had long since waved goodbye to Wareville, and the crisp night air was creeping in through the window of McSkidy's office. If only there were a substance which would both warm and wake her up. Once McSkidy's brain cells had started functioning again, and remembered that coffee existed. Checking her watch, she was saddened to learn it was too late to get her coffee from her favorite Wareville coffee house, Splunkin Donuts; the vending machine downstairs would have to do. Sipping her coffee, McSkidy immediately lit up and charged back into the office, ready to crack the case; however, as she entered, the Glitch had an idea of his own. He'd got it, and he figured out an attack vector the user had likely taken! McSkidy took a seat next to the Glitch, and he began to walk it through.

![Azure logo wrapped in Xmas decorations](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1730822466501.png)

This is the continuation of [day 15](DAY%2015.md) 
## Learning Objectives
---

```ad-summary
- Learn about Azure, what it is and why it is used.
- Learn about Azure services like Azure Key Vault and Microsoft Entra ID.
- Learn how to interact with an Azure tenant using Azure Cloud Shell.
```

## Intro to Azure
---

Before diving into the Glitch's idea of the attacker's path, let's introduce some of the key concepts that will be covered in the process. We are going to start by introducing Azure. To do that, let's consider why McSkidy is using Azure in the first place.

It all started when McSkidy's role as the cyber security expert of Wareville really started to take off. Before she knew it, McSkidy was in very high demand and needed to create all kinds of resources to help her organize her duties; these included a web application to handle appointment making, multiple machines running for investigations, and more machines running for evidence storing and analysis. McSkidy hosted and managed all of these machines herself, that is, on-prem (on-premises). This initially wasn't a massive issue because, after all, she wasn't a corporation but just helping the citizens of Wareville with cyber security matters.

However, as time went on, McSkidy ran into issues during peak times when she would receive many requests for help, and therefore needed to process more evidence. All of this increased demand meant McSkidy had to scale up her resources to handle the load. To put a long story short, this was a lot of hassle for McSkidy. She wished there was a way for someone to handle her infrastructure on her behalf, especially when scaling her resources up (during peak times) and down (when they resumed). That's when Azure came to the rescue.

![McSkidy and Azure working together in office](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1730822510157.png) 

Azure is a CSP (Cloud Service Provider), and CSPs (others include Google Cloud and AWS) provide computing resources such as computing power on demand in a highly scalable fashion. In other words, McSkidy could instead have Azure manage her underlying infrastructure, scaling it in times of increased demand and decreasing it once traffic resumed to normal levels. The best bit? McSkidy only has to pay for what she uses; gone were the days of buying physical infrastructure to handle increased loads, only for that infrastructure to go unused the majority of the time. 

Azure (and cloud adoption in general) boasts many benefits beyond cost optimization. Azure also gave McSkidy access to lots of cloud services ranging from identity management to data ingestion (quite frankly, there are more services than can be abbreviated in a sentence as, at the time of writing, there are over 200), these services can be used to build, deploy, and manage McSkidy's current infrastructure as well as give her the options to upgrade or build new applications in the future given the range of services available. A couple of Azure services will come up during the Glitch's attack path. Let's take a look at them now:

**Azure Key Vault**

Azure Key Vault is an Azure service that allows users to securely store and access secrets. These secrets can be anything from API Keys, certificates, passwords, cryptographic keys, and more. Essentially, anything you want to keep safe, away from the eyes of others, and easily configure and restrict access to is what you want to store in an Azure Key Vault.

The secrets are stored in vaults, which are created by vault owners. Vault owners have full access and control over the vault, including the ability to enable auditing so a record is kept of who accessed what secrets and grant permissions for other users to access the vault (known as **vault consumers**). McSkidy uses this service to store secrets related to evidence and has been entrusted to store some of Wareville's town secrets here.

**Microsoft Entra ID**

McSkidy also needed a way to grant users access to her system and be able to secure and organise their access easily. So, a Wareville town member could easily access or update their secret. Microsoft Entra ID (formerly known as Azure Active Directory) is Azure's solution. Entra ID is an identity and access management (IAM) service. In short, it has the information needed to assess whether a user/application can access X resource. In the case of the Wareville town members, they made an Entra ID account, and McSkidy assigned the appropriate permissions to this account.

With that covered, let's see what the Glitch has come up with.

## Assumed Breach Scenario
----


Knowing that a potential breach had happened, McSkidy decided to conduct an Assumed Breach testing within their Azure tenant. The Assumed Breach scenario is a type of penetration testing setup in which an initial access or foothold is provided, mimicking the scenario in which an attacker has already established its access inside the internal network.

In this setup, the mindset is to assess how far an attacker can go once they get inside your network, including all possible attack paths that could branch out from the defined starting point of intrusion.


For this Assumed Breach testing of Wareville's tenant, McSkidy will provide valid credentials. To get the credentials, click the **Cloud Details** button below.

Next, click the **Join Lab** button to generate your credentials.

![Generating credentials for Azure.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022044862.png) 

You may view the credentials by clicking the **Credentials** tab.

![Viewing the credentials in the Credentials tab.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022071488.png) 

To use the credentials, click the **Open Lab** button in the **Environment** tab. This will open the [Azure Portal](https://portal.azure.com/) login page, so kindly use the recently generated credentials to authenticate to the Azure Portal. ![Going to the Azure Portal via the Open Lab button.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022209026.png) 

After logging in, you will encounter an MFA configuration prompt. Kindly click the **Ask Later** button to proceed.

![Skipping the MFA configuration.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022425034.png) 

Lastly, click the **Cancel** button when prompted with the **Welcome to Microsoft Azure** banner.

![Skipping the Azure welcome banner.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022425433.png)

**Note:** The Azure Portal may default to your local language, so you may follow these steps if you prefer to switch it to English.

```ad-summary
1. Click on the settings icon in the top panel.
2. On the right-hand side, click on "Language + Region".
3. Change the language to English (or your preferred choice) using the dropdown menu.
4. Click the "Apply" button below.
```

![Configuring the language settings.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1732022969184.png)



**Azure Cloud Shell**

Azure Cloud Shell is a browser-based command-line interface that provides developers and IT professionals a convenient and powerful way to manage Azure resources. It integrates both Bash and PowerShell environments, allowing users to execute scripts, manage Azure services, and run commands directly from their web browser without needing local installation. Cloud Shell has built-in tools and pre-configured environments, including Azure CLI, Azure PowerShell, and popular development tools, making it an efficient solution for cloud management and automation tasks.

**Azure CLI**

Azure Command-Line Interface, or Azure CLI, is a command-line tool for managing and configuring Azure resources. The Glitch relied heavily on this tool while reviewing the Wareville tenant, so let's use the same one while walking through the Azure attack path.

As mentioned above, Azure CLI is part of the built-in tools inside the Cloud Shell, so go back to the [Azure portal](https://portal.azure.com/) and launch Azure Cloud Shell by clicking on the terminal icon shown below:

![Azure Portal Cloud Shell button.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1731679657004.png) 

Select Bash, since we will be executing Azure CLI commands.

![Bash or PowerShell options for Azure Cloud Shell.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efbaebdaaea011c857b438d/room-content/5efbaebdaaea011c857b438d-1729952192089.png)

To get started, select`No storage account required` and choose`Az-Subs-AoC` for the subscription.

![Getting started instructions for Azure Cloud Shell.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efbaebdaaea011c857b438d/room-content/5efbaebdaaea011c857b438d-1729952373608.png)

![Initial Azure Cloud Shell prompt.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efbaebdaaea011c857b438d/room-content/5efbaebdaaea011c857b438d-1729952645147.png)

At this point, we are ready to execute Azure CLI commands in the Azure Cloud Shell. Note that all the following commands are to be executed in the Azure Cloud Shell. 


```shell-session
usr-xxxxxxxx [ ~ ]$ az ad signed-in-user show
```

**Note:** You don't need to authenticate using`az login` as you have already been authenticated into the Azure portal. 

You can confirm that the credentials worked if the succeeding output renders the authenticated user details.


```shell-session
{
 "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
 "businessPhones": [],
 "displayName": "usr-xxxxxxxx",
 "givenName": null,
 "id": "3970058b-7741-49c5-b1a7-191540995f7a",
 "jobTitle": null,
 "mail": null,
 "mobilePhone": null,
 "officeLocation": null,
 "preferredLanguage": null,
 "surname": null,
 "userPrincipalName": "usr-xxxxxxxx@aoc2024.onmicrosoft.com"
}
```

## Going Down the Azure Rabbit Hole

When the Glitch got hold of an initial account in Wareville's Azure tenant, he had no idea what was inside it. So, he decided to enumerate first the existing users and groups within the tenant.

**Entra ID Enumeration**

Using the current account, let's start by listing all the users in the tenant. **Note:** This command might take a while depending on the amount of user accounts available, so feel free to skip it.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az ad user list
```

 
The Azure CLI typically uses the following command syntax:`az GROUP SUBGROUP ACTION OPTIONAL_PARAMETERS`. Given this, the command above can be broken down into:

- Target group or service:`ad` (Azure AD or Entra ID)
- Target subgroup:`user` (Azure AD users)
- Action:`list`

**Note:** To see the available commands, you may execute`az -h` or`az GROUP -h`.

After executing the command, you might have been overwhelmed with the number of accounts listed. For a better view, let's follow McSkidy's suggestion to only look for the accounts prepended with`wvusr-`. According to her, these accounts are more interesting than the other ones. To do this, we will use the`--filter` parameter and filter all accounts that start with`wvusr-`.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az ad user list --filter "startsWith('wvusr-', displayName)"
```

 
You may observe that an unusual parameter was set to a specific account in the output. One of the users, **wvusr-backupware**, has its password stored in one of the fields.```shell-session
...
 {
 "businessPhones": [],
 "displayName": "wvusr-backupware",
 "givenName": null,
 "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
 "jobTitle": null,
 "mail": null,
 "mobilePhone": null,
 "officeLocation": "REDACTED",
 "preferredLanguage": null,
 "surname": null,
 "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
 },
...
```

 
When the Glitch saw this one, he immediately thought it could be the first step taken by the intruder to gain further access inside the tenant. However, he decided to continue the initial reconnaissance of users and groups. Now, let's continue by listing the groups.



```shell-session
usr-xxxxxxxx [ ~ ]$ az ad group list
[
 {
 ---REDACTED FOR BREVITY---
 "description": "Group for recovering Wareville's secrets",
 "displayName": "Secret Recovery Group",
 "expirationDateTime": null,
 ---REDACTED FOR BREVITY---
 }
]
```

 
**Note:** You may observe that we just changed the previous command from`az ad user list` to`az ad group list`. Given the output, it can be seen that a group named`Secret Recovery Group` exists. This is kind of an interesting group because of the description, so let's follow the white rabbit and list the members of this group.


```shell-session
usr-xxxxxxxx [ ~ ]$ az ad group member list --group "Secret Recovery Group"
[
 {
 "@odata.type": "#microsoft.graph.user",
 "businessPhones": [],
 "displayName": "wvusr-backupware",
 ---REDACTED FOR BREVITY---
 }
]
```

 
Given the previous output, it looks like everything makes a little sense now. All of the previous commands seem to point to the`wvusr-backupware` account. Since we have seen a potential set of credentials, let's jump to another user by clearing the current Azure CLI account session and logging in with the new account.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az account clear
usr-xxxxxxxx [ ~ ]$ az login -u EMAIL -p PASSWORD
```

 
**Note:** Replace the values with the actual email and password of the newly discovered account.

**Azure Role Assignments** 

Since the`wvusr-backupware` account belongs to an interesting group, the Glitch's first hunch is to see whether sensitive or privileged roles are assigned to the group. And his thought was, "It doesn't make sense to name it like this if it can't do anything, right McSkidy?". But before checking the assigned roles, let's have a quick run-through of Azure Role Assignments.

**Azure Role Assignments** define the resources that each user or group can access. When a new user is created via Entra ID, it cannot access any resource by default due to a lack of role. To grant access, an administrator must assign a **role** to let users view or manage a specific resource. The privilege level configured in a role ranges from read-only to full-control. Additionally, **group members can inherit a role** when assigned to a group. 

Returning to the Azure enumeration, let's see if a role is assigned to the Secret Recovery Group. We will be using the`--all` option to list all roles within the Azure subscription, and we will be using the`--assignee` option with the group's ID to render only the ones related to our target group.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az role assignment list --assignee REPLACE_WITH_SECRET_RECOVERY_GROUP_ID --all
[
 {
 ---REDACTED FOR BREVITY---
 "principalName": "Secret Recovery Group",
 "roleDefinitionName": "Key Vault Secrets User",
 "scope": "/subscriptions/{subscriptionId}/resourceGroups/rog-aoc-kv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
 ---REDACTED FOR BREVITY---
 },
 {
 ---REDACTED FOR BREVITY---
 "principalName": "Secret Recovery Group",
 "roleDefinitionName": "Key Vault Reader",
 "scope": "/subscriptions/{subscriptionId}/resourceGroups/rog-aoc-kv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
 ---REDACTED FOR BREVITY---
 }
]
```

 
**Note:** You may retrieve the group ID from the command executed previously:`az ad group list`.

The output seems slightly overwhelming, so let's break it down.

- First, it can be seen that there are two entries in the output, which means two roles are assigned to the group.
- Based on the`roleDefinitionName` field, the two roles are`Key Vault Reader` and`Key Vault Secrets User`.
- Both entries have the same scope value, pointing to a Microsoft Key Vault resource, specifically on the`warevillesecrets` vault.

Here's the definition of the roles based on the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles):

| | | |
|---|---|---|
|**Role**|**Microsoft Definition**|**Explanation**|
|Key Vault Reader|Read metadata of key vaults and its certificates, keys, and secrets.|This role allows you to read metadata of key vaults and its certificates, keys, and secrets. Cannot read sensitive values such as secret contents or key material.|
|Key Vault Secrets User|Read secret contents. Only works for key vaults that use the 'Azure role-based access control' permission model.|This special role allows you to read the contents of a Key Vault Secret.|

After seeing both of these roles, McSkidy immediately realised everything! This configuration allowed the attacker to access the sensitive data they were protecting. Now that she knew this, she asked the Glitch to confirm her assumption.

**Azure Key Vault**

With McSkidy's guidance, the Glitch is now tasked to verify if the current account, **wvusr-backupware**, can access the sensitive data. Let's list the accessible key vaults by executing the command below.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az keyvault list
[
 {
 "id": "/subscriptions/{subscriptionId}/resourceGroups/rog-aoc-kv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
 "location": "eastus",
 "name": "warevillesecrets",
 "resourceGroup": "rg-aoc-kv",
 "tags": {
 "aoc": "rg"
 },
 "type": "Microsoft.KeyVault/vaults"
 }
]
```

 
The output above confirms the key vault discovered from the role assignments named`warevillesecrets`. Now, let's see if secrets are stored in this key vault.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az keyvault secret list --vault-name warevillesecrets
[
 {
 ---REDACTED FOR BREVITY---
 "id": "https://warevillesecrets.vault.azure.net/secrets/REDACTED",
 "managed": null,
 "name": "REDACTED",
 "tags": {}
 }
]
```

 
After executing the two previous commands, we confirmed that the **Reader** role allows us to view the key vault metadata, specifically the list of key vaults and secrets. Now, the only thing left to confirm is whether the current user can access the contents of the discovered secret with the **Key Vault Secrets User** role. This can be done by executing the following command.

Azure Cloud Shell

```shell-session
usr-xxxxxxxx [ ~ ]$ az keyvault secret show --vault-name warevillesecrets --name REDACTED
{
 ---REDACTED FOR BREVITY---
 "id": "https://warevillesecrets.vault.azure.net/secrets/REDACTED/20953fbf6d51464299b30c6356b378fd",
 "kid": null,
 "managed": null,
 "name": "REDACTED",
 "tags": {},
 "value": "REDACTED"
}
```

**Note:** Replace the value of the`--name` parameter with the actual secret name.

"Bingo!" the Glitch exclaimed as he saw the output above. McSkidy had confirmed her nightmare that a regular user could escalate their way into the secrets of Wareville.

With that, the Glitch had helped McSkidy to find the attack path that had been taken to escalate a userâ€™s privileges and a lot had been learned in the process. The only question that remained was who had initially carried out the attack in the first place. There was a very limited set of Wares who had access to this tenant and with user visibility, and with that set of permissions, only town officials who perform governance validation on the tenant to ensure all the townâ€™s secrets are being stored securely. The focus then turns to the motive; the only thing accessed was an access key stored in the key vault, which grants access to an evidence file stored elsewhere. The evidence in this file was in relation to recent cyber events this month in Wareville. Weâ€™ll have to keep our eyes peeled in the following days to get to the bottom of this.

## Questions

<iframe width="900" height="690" src="https://www.youtube.com/embed/t1_FG5IUBcs" title="TryHackMe | Advent of Cyber 2024: Day 16 (Azure)" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

![Pasted image 20241216213542.png](../../IMAGES/Pasted%20image%2020241216213542.png)

To view the explanation for each question, check the video, didn't have much time today, just like that, day 16 is done.

