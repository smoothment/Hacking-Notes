# Introduction

---

Microsoft's Active Directory is the backbone of the corporate world. It simplifies the management of devices and users within a corporate environment. In this room, we'll take a deep dive into the essential components of Active Directory.

Room Objectives

In this room, we will learn about Active Directory and will become familiar with the following topics

- What Active Directory is
- What an Active Directory Domain is
- What components go into an Active Directory Domain
- Forests and Domain Trust
- And much more!

Room Prerequisites

- General familiarity with Windows. Check theÂ [Windows Fundamentals module](https://tryhackme.com/module/windows-fundamentals)Â for more information on this.
  
# Windows Domains

---


Picture yourself administering a small business network with only five computers and five employees. In such a tiny network, you will probably be able to configure each computer separately without a problem. You will manually log into each computer, create users for whoever will use them, and make specific configurations for each employee's accounts. If a user's computer stops working, you will probably go to their place and fix the computer on-site.

While this sounds like a very relaxed lifestyle, let's suppose your business suddenly grows and now has 157 computers and 320 different users located across four different offices. Would you still be able to manage each computer as a separate entity, manually configure policies for each of the users across the network and provide on-site support for everyone? The answer is most likely no.

To overcome these limitations, we can use a Windows domain. Simply put, aÂ **Windows domain**Â is a group of users and computers under the administration of a given business. The main idea behind a domain is to centralise the administration of common components of a Windows computer network in a single repository calledÂ **Active Directory (AD)**. The server that runs the Active Directory services is known as aÂ **Domain Controller (DC)**.

![Windows Domain Overview](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/bebe5dfec0208bf563d01fa2dd1fb7a7.png)

The main advantages of having a configured Windows domain are:

- **Centralised identity management:**Â All users across the network can be configured from Active Directory with minimum effort.
- **Managing security policies:**Â You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.

A Real-World Example

If this sounds a bit confusing, chances are that you have already interacted with a Windows domain at some point in your school, university or work.

In school/university networks, you will often be provided with a username and password that you can use on any of the computers available on campus. Your credentials are valid for all machines because whenever you input them on a machine, it will forward the authentication process back to the Active Directory, where your credentials will be checked. Thanks to Active Directory, your credentials don't need to exist in each machine and are available throughout the network.

Active Directory is also the component that allows your school/university to restrict you from accessing the control panel on your school/university machines. Policies will usually be deployed throughout the network so that you don't have administrative privileges over those computers.


# Active Directory

---

ï»¿The core of any Windows Domain is theÂ **Active Directory Domain Service (ADÂ DS)**. This service acts as a catalogue that holds the information of all of the "objects" that exist on your network. Amongst the many objects supported byÂ AD, we have users, groups, machines, printers, shares and many others. Let's look at some of them:

**_Users_**

Users are one of the most common object types in Active Directory. Users are one of the objects known asÂ **security principals**, meaning that they can be authenticated by the domain and can be assigned privileges overÂ **resources**Â like files or printers. You could say that a security principal is an object that can act upon resources in the network.

Users can be used to represent two types of entities:

- **People:**Â users will generally represent persons in your organisation that need to access the network, like employees.
- **Services:**Â you can also define users to be used by services like IIS or MSSQL. Every single service requires a user to run, but service users are different from regular users as they will only have the privileges needed to run their specific service.

**_Machines_**

Machines are another type of object within Active Directory; for every computer that joins the Active Directory domain, a machine object will be created. Machines are also considered "security principals" and are assigned an account just as any regular user. This account has somewhat limited rights within the domain itself.

The machine accounts themselves are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in.

**Note:**Â Machine Account passwords are automatically rotated out and are generally comprised of 120 random characters.

Identifying machine accounts is relatively easy. They follow a specific naming scheme. The machine account name is the computer's name followed by a dollar sign. For example, a machine namedÂ `DC01`Â will have a machine account calledÂ `DC01$`.

**_Security Groups_**

If you are familiar with Windows, you probably know that you can define user groups to assign access rights to files or other resources to entire groups instead of single users. This allows for better manageability as you can add users to an existing group, and they will automatically inherit all of the group's privileges. Security groups are also considered security principals and, therefore, can have privileges over resources on the network.

Groups can have both users and machines as members. If needed, groups can include other groups as well.

Several groups are created by default in a domain that can be used to grant specific privileges to users. As an example, here are some of the most important groups in a domain:

|   |   |
|---|---|
|**Security Group**|**Description**|
|Domain Admins|Users of this group have administrative privileges over the entire domain. By default, they can administer any computer on the domain, including the DCs.|
|Server Operators|Users in this group can administer Domain Controllers. They cannot change any administrative group memberships.|
|Backup Operators|Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers.|
|Account Operators|Users in this group can create or modify other accounts in the domain.|
|Domain Users|Includes all existing user accounts in the domain.|
|Domain Computers|Includes all existing computers in the domain.|
|Domain Controllers|Includes all existing DCs on the domain.|

You can obtain the complete list of default security groups from theÂ [Microsoft documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups).  

### Active Directory Users and Computers

To configure users, groups or machines in Active Directory, we need to log in to the Domain Controller and run "Active Directory Users and Computers" from the start menu:

![Start menu AD Users and Computers](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/11d01963392078c1450300d2881f9160.png)

This will open up a window where you can see the hierarchy of users, computers and groups that exist in the domain. These objects are organised inÂ **Organizational Units (OUs)**Â which areÂ containerÂ objects that allow you to classify users and machines. OUs are mainly used to define sets of users with similar policing requirements. The people in the Sales department of your organisation are likely to have a different set of policies applied than the people in IT, for example. Keep in mind that a user can only be a part of a singleÂ OUÂ at a time.

Checking our machine, we can see that there is already anÂ OUÂ calledÂ `THM`Â with four child OUs for the IT, Management, Marketing and Sales departments. It is very typical to see the OUs mimic the business' structure, as it allows for efficiently deploying baseline policies that apply to entire departments. Remember that while this would be the expected model most of the time, you can define OUs arbitrarily. Feel free to right-click theÂ `THM`Â OU and create a new OU under it calledÂ `Students`Â just for the fun of it.

![AD Users and Computers](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c5b1d321108bc065771eba62d24f5e83.png)

If you open any OUs, you can see the users they contain and perform simple tasks like creating, deleting or modifying them as needed. You can also reset passwords if needed (pretty useful for the helpdesk):

![IT department OU](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/76e01efece5a00cc91f7099226130c5c.png)

You probably noticed already that there are other default containers apart from theÂ THMÂ OU. These containers are created by Windows automatically and contain the following:

- **Builtin:**Â Contains default groups available to any Windows host.
- **Computers:**Â Any machine joining the network will be put here by default. You can move them if needed.
- **Domain Controllers:**Â DefaultÂ OUÂ that contains the DCs in your network.
- **Users:**Â Default users and groups that apply to a domain-wide context.
- **Managed Service Accounts:**Â Holds accounts used by services in your Windows domain.

### Security Groups vs OUs

You are probably wondering why we have both groups and OUs. While both are used to classify users and computers, their purposes are entirely different:

- **OUs**Â are handy forÂ **applying policies**Â to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. Remember, a user can only be a member of a singleÂ OUÂ at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.
- **Security Groups**, on the other hand, are used toÂ **grant permissions over resources**. For example, you will use groups if you want to allow some users to access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources.

![Pasted image 20250526121454.png](../../../IMAGES/Pasted%20image%2020250526121454.png)

# Managing Users in AD

---

Your first task as the new domain administrator is to check the existingÂ ADÂ OUs and users, as some recent changes have happened to the business. You have been given the following organisational chart and are expected to make changes to theÂ ADÂ to match it:

![THM Organisational Chart](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/88f0ade5a672ae681639e6049406a4ec.png)

### Deleting extra OUs and users

The first thing you should notice is that there is an additional departmentÂ OUÂ in your currentÂ ADÂ configuration that doesn't appear in the chart. We've been told it was closed due to budget cuts and should be removed from the domain. If you try to right-click and delete theÂ OU, you will get the following error:

![OU delete error](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/38edaf4a8665c257c62556096c69cb6f.png)

By default, OUs are protected against accidental deletion. To delete theÂ OU, we need to enable theÂ **Advanced Features**Â in the View menu:

![Enabling advanced features](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/15b282b6e3940f4c26c477a8c21f8266.png)

This will show you some additional containers and enable you to disable the accidental deletion protection. To do so, right-click theÂ OUÂ and go to Properties. You will find a checkbox in the Object tab to disable the protection:

![Disable OU delete protection](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/ad6b6d886c0448d14ce4ec8c62250256.png)

Be sure to uncheck the box and try deleting theÂ OUÂ again. You will be prompted to confirm that you want to delete theÂ OU, and as a result, any users, groups or OUs under it will also be deleted.

After deleting the extraÂ OU, you should notice that for some of the departments, the users in theÂ ADÂ don't match the ones in our organisational chart. Create and delete users as needed to match them.

### Delegation

One of the nice things you can do inÂ ADÂ is to give specific users some control over some OUs. This process is known asÂ **delegation**Â and allows you to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Administrator to step in.

One of the most common use cases for this is grantingÂ `IT support`Â the privileges to reset other low-privilege users' passwords. According to our organisational chart, Phillip is in charge of IT support, so we'd probably want to delegate the control of resetting passwords over the Sales, Marketing and Management OUs to him.

For this example, we will delegate control over the SalesÂ OUÂ to Phillip. To delegate control over anÂ OU, you can right-click it and selectÂ **Delegate Control**:

![Delegating OU control](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/74f8d615658a03aeb1cfdb6767d0a0a3.png)

This should open a new window where you will first be asked for the users to whom you want to delegate control:

**Note:**Â To avoid mistyping the user's name, write "phillip" and click theÂ **Check Names**Â button. Windows will autocomplete the user for you.

![Delegating Sales OU to Phillip](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2814715e1dbadaef334973028e02da69.png)  

Click OK, and on the next step, select the following option:

![Delegating password resets](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3f81df2b38e35ca5729aee7a76c6b220.png)

Click next a couple of times, and now Phillip should be able to reset passwords for any user in the sales department. While you'd probably want to repeat these steps to delegate the password resets of the Marketing and Management departments, we'll leave it here for this task. You are free to continue to configure theÂ restÂ of the OUs if you so desire.

Now let's use Phillip's account to try and reset Sophie's password. Here are Phillip's credentials for you to log in viaÂ RDP:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fb7768e14470fc6b51d6fe2cc991cd6f.png)

|   |   |
|---|---|
|**Username**|phillip|
|**Password**|Claire2008|

**Note:**Â When connecting viaÂ RDP, useÂ `THM\phillip`Â as the username to specify you want to log in using the userÂ `phillip`Â on theÂ `THM`Â domain.

While you may be tempted to go toÂ **Active Directory Users and Computers**Â to try and test Phillip's new powers, he doesn't really have the privileges to open it, so you'll have to use other methods to do password resets. In this case, we will be usingÂ PowershellÂ to do so:

WindowsPowerShell(As Phillip)

```shell-session
PS C:\Users\phillip> Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

New Password: *********

VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```

Since we wouldn't want Sophie to keep on using a password we know, we can also force a password reset at the next logon with the following command:

WindowsPowerShell(as Phillip)

```shell-session
PS C:\Users\phillip> Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose

VERBOSE: Performing the operation "Set" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/6b8f51d10ceb9f15befa885ab116d2d6.png)Log into Sophie's account with your new password and retrieve a flag from Sophie's desktop.

**Note:**Â When connecting viaÂ RDP, useÂ `THM\sophie`Â as the username to specify you want to log in using the userÂ `sophie`Â on theÂ `THM`Â domain.

![Pasted image 20250526121532.png](../../../IMAGES/Pasted%20image%2020250526121532.png)

# Managing Computers in AD

---

By default, all the machines that join a domain (except for the DCs) will be put in theÂ containerÂ called "Computers". If we check ourÂ DC, we will see that some devices are already there:

![Computers OU](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a1d41d5437e73d62ede10f2015dc4dfc.png)

We can see some servers, some laptops and some PCs corresponding to the users in our network. Having all of our devices there is not the best idea since it's very likely that you want different policies for your servers and the machines that regular users use on a daily basis.

While there is no golden rule on how to organise your machines, an excellent starting point is segregating devices according to their use. In general, you'd expect to see devices divided into at least the three following categories:

**1. Workstations**

Workstations are one of the most common devices within an Active Directory domain. Each user in the domain will likely be logging into a workstation. This is the device they will use to do their work or normal browsing activities. These devices should never have a privileged user signed into them.  

**2. Servers**

Servers are the second most common device within an Active Directory domain. Servers are generally used to provide services to users or other servers.

**3. Domain Controllers**

Domain Controllers are the third most common device within an Active Directory domain. Domain Controllers allow you to manage the Active Directory Domain. These devices are often deemed the most sensitive devices within the network as they contain hashed passwords for all user accounts within the environment.

Since we are tidying up ourÂ AD, let's create two separate OUs forÂ `Workstations`Â andÂ `Servers`Â (Domain Controllers are already in an OU created by Windows). We will be creating them directly under theÂ `thm.local`Â domainÂ container. In the end, you should have the followingÂ OUÂ structure:

![final OU structure](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/09405010962071f21c6dee7b4eb8c59a.png)

Now, move the personal computers and laptops to the WorkstationsÂ OUÂ and the servers to the ServersÂ OUÂ from the ComputersÂ container. Doing so will allow us to configure policies for eachÂ OUÂ later.

![Pasted image 20250526121639.png](../../../IMAGES/Pasted%20image%2020250526121639.png)


# Group Policies

---

So far, we have organised users and computers in OUs just for the sake of it, but the main idea behind this is to be able to deploy different policies for eachÂ OUÂ individually. That way, we can push different configurations and security baselines to users depending on their department.

Windows manages such policies throughÂ **Group Policy Objects (GPO)**. GPOs are simply a collection of settings that can be applied to OUs. GPOs can contain policies aimed at either users or computers, allowing you to set a baseline on specific machines and identities.

To configure GPOs, you can use theÂ **Group Policy Management**Â tool, available from the start menu:

![Start menu GPM](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/b19052c41e27fbbb2651038cede63e11.png)

The first thing you will see when opening it is your completeÂ OUÂ hierarchy, as defined before. To configure Group Policies, you first create aÂ GPOÂ underÂ **Group Policy Objects**Â and then link it to theÂ OUÂ where you want the policies to apply. As an example, you can see there are some already existing GPOs in your machine:

![Existing OUs in your machine](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d82cb9440894c831f6f3d58a2b0538ed.png)  

We can see in the image above that 3 GPOs have been created. From those, theÂ `Default Domain Policy`Â andÂ `RDP Policy`Â are linked to theÂ `thm.local`Â domain as a whole, and theÂ `Default Domain Controllers Policy`Â is linked to theÂ `Domain Controllers`Â OU only. Something important to have in mind is that any GPO will apply to the linked OU and any sub-OUs under it. For example, theÂ `Sales`Â OUÂ will still be affected by theÂ `Default Domain Policy`.

Let's examine theÂ `Default Domain Policy`Â to see what's inside a GPO. The first tab you'll see when selecting a GPO shows itsÂ **scope**, which is where the GPO is linked in the AD. For the current policy, we can see that it has only been linked to theÂ `thm.local`Â domain:

![OU scope](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/06d5e70fbfa648f73e4598e18c8e9527.png)  

As you can see, you can also applyÂ **Security Filtering**Â to GPOs so that they are only applied to specific users/computers under anÂ OU. By default, they will apply to theÂ **Authenticated Users**Â group, which includes all users/PCs.

TheÂ **Settings**Â tab includes the actual contents of theÂ GPOÂ and lets us know what specific configurations it applies. As stated before, eachÂ GPOÂ has configurations that apply to computers only and configurations that apply to users only. In this case, theÂ `Default Domain Policy`Â only contains Computer Configurations:

![OU Settings](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c9293853549d5126b77bf2de8086e076.png)  

Feel free to explore theÂ GPOÂ and expand on the available items using the "show" links on the right side of each configuration. In this case, theÂ `Default Domain Policy`Â indicates really basic configurations that should apply to most domains, including password and account lockout policies:

![OU detailed settings](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a5f4c2605062934579c64f2cfa025308.png)

Since thisÂ GPOÂ applies to the whole domain, any change to it would affect all computers. Let's change the minimum password length policy to require users to have at least 10 characters in their passwords. To do this, right-click theÂ GPOÂ and selectÂ **Edit**:

![Editing a GPO settings](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/b71d8de9e74d129d0ad4142863deadc4.png)  

This will open a new window where we can navigate and edit all the available configurations. To change the minimum password length, go toÂ `Computer Configurations -> Policies -> Windows Setting -> Security Settings -> Account Policies -> Password Policy`Â and change the required policy value:

![Password policy GPO](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/bd3665c2569aa8fbe4f7482a5750f018.png)  

As you can see, plenty of policies can be established in aÂ GPO. While explaining every single of them would be impossible in a single room, do feel free to explore a bit, as some of the policies are straightforward. If more information on any of the policies is needed, you can double-click them and read theÂ **Explain**Â tab on each of them:

![OU settings explain tab](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/de35e7c03fafcb5b9df5457181e32652.png)  

GPOÂ distribution

GPOs are distributed to the network via a network share calledÂ `SYSVOL`, which is stored in the DC. All users in a domain should typically have access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to theÂ `C:\Windows\SYSVOL\sysvol\`Â directory on each of the DCs in our network.

Once a change has been made to any GPOs, it might take up to 2 hours for computers to catch up. If you want to force any particular computer to sync its GPOs immediately, you can always run the following command on the desired computer:

WindowsPowerShell

```shell-session
PS C:\> gpupdate /force
```

Creating some GPOs forÂ THMÂ Inc.

As part of our new job, we have been tasked with implementing some GPOs to allow us to:

1. Block non-IT users from accessing the Control Panel.
2. Make workstations and servers lock their screen automatically after 5 minutes of user inactivity to avoid people leaving their sessions exposed.

Let's focus on each of those and define what policies we should enable in eachÂ GPOÂ and where they should be linked.

**_Restrict Access to Control Panel_**

We want to restrict access to the Control Panel across all machines to only the users that are part of the IT department. Users of other departments shouldn't be able to change the system's preferences.

Let's create a newÂ GPOÂ calledÂ `Restrict Control Panel Access`Â and open it for editing. Since we want this GPO to apply to specific users, we will look underÂ `User Configuration`Â for the following policy:

![Restricting access to control panel](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9b333a11d12f05dd4413e3f208aab363.png)  

Notice we have enabled theÂ **Prohibit Access to Control Panel and PC settings**Â policy.

Once theÂ GPOÂ is configured, we will need to link it to all of the OUs corresponding to users who shouldn't have access to the Control Panel of their PCs. In this case, we will link theÂ `Marketing`,Â `Management`Â andÂ `Sales`Â OUs by dragging theÂ GPOÂ to each of them:

![Linking Restrict Control Panel GPO](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/4a8f727788731b7fbf87fc079682d1a6.png)  

**_Auto Lock ScreenÂ GPO_**

For the firstÂ GPO, regarding screen locking for workstations and servers, we could directly apply it over theÂ `Workstations`,Â `Servers`Â andÂ `Domain Controllers`Â OUs we created previously.

While this solution should work, an alternative consists of simply applying theÂ GPOÂ to the root domain, as we want theÂ GPOÂ to affect all of our computers. Since theÂ `Workstations`,Â `Servers`Â andÂ `Domain Controllers`Â OUs are all child OUs of the root domain, they will inherit its policies.

**Note:**Â You might notice that if ourÂ GPOÂ is applied to the root domain, it will also be inherited by other OUs likeÂ `Sales`Â orÂ `Marketing`. Since these OUs contain users only, any Computer Configuration in ourÂ GPOÂ will be ignored by them.

Let's create a newÂ GPO, call itÂ `Auto Lock Screen`, and edit it. The policy to achieve what we want is located in the following route:

![Configuring machine inactivity limit](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/44c0cde18837cb6333c78749356ac0ee.png)  

We will set the inactivity limit to 5 minutes so that computers get locked automatically if any user leaves their session open. After closing theÂ GPOÂ editor, we will link theÂ GPOÂ to the root domain by dragging theÂ GPOÂ to it:

![Linking Auto Lock Screen GPO](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fcfc77d126991ffee8c927202b4dde37.png)

Once the GPOs have been applied to the correct OUs, we can log in as any users in either Marketing, Sales or Management for verification. For this task, let's connect viaÂ RDPÂ using Mark's credentials:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fb7768e14470fc6b51d6fe2cc991cd6f.png)

|   |   |
|---|---|
|**Username**|Mark|
|**Password**|M4rk3t1ng.21|

Note:Â When connecting viaÂ RDP, useÂ `THM\Mark`Â as the username to specify you want to log in using the userÂ `Mark`Â on theÂ `THM`Â domain.  

If we try opening the Control Panel, we should get a message indicating this operation is denied by the administrator. You can also wait 5 minutes to check if the screen is automatically locked if you want.

Since we didn't apply the control panel GPO on IT, you should still be able to log into the machine as any of those users and access the control panel.Â 

**Note:**Â If you created and linked the GPOs, but for some reason, they still don't work, remember you can runÂ `gpupdate /force`Â to force GPOs to be updated.


![Pasted image 20250526121709.png](../../../IMAGES/Pasted%20image%2020250526121709.png)

  
# Authentication Methods

---

When using Windows domains, all credentials are stored in the Domain Controllers. Whenever a user tries to authenticate to a service using domain credentials, the service will need to ask the Domain Controller to verify if they are correct. Two protocols can be used for network authentication in windows domains:

- **Kerberos:**Â Used by any recent version of Windows. This is the default protocol in any recent domain.
- **NetNTLM:**Â Legacy authentication protocol kept for compatibility purposes.

While NetNTLM should be considered obsolete, most networks will have both protocols enabled. Let's take a deeper look at how each of these protocols works.

## KerberosÂ Authentication

KerberosÂ authentication is the default authentication protocol for any recent version of Windows. Users who log into a service usingÂ KerberosÂ will be assigned tickets. Think of tickets as proof of a previous authentication. Users with tickets can present them to a service to demonstrate they have already authenticated into the network before and are therefore enabled to use it.

WhenÂ KerberosÂ is used for authentication, the following process happens:

1. The user sends their username and a timestamp encrypted using a key derived from their password to theÂ **Key Distribution Center (KDC)**, a service usually installed on the Domain Controller in charge of creatingÂ KerberosÂ tickets on the network.
    
    The KDC will create and send back aÂ **Ticket Granting Ticket (TGT)**, which will allow the user to request additional tickets to access specific services. The need for a ticket to get more tickets may sound a bit weird, but it allows users to request service tickets without passing their credentials every time they want to connect to a service. Along with theÂ TGT, aÂ **Session Key**Â is given to the user, which they will need to generate the following requests.
    
    Notice theÂ TGTÂ is encrypted using theÂ **krbtgt**Â account's password hash, and therefore the user can't access its contents. It is essential to know that the encryptedÂ TGTÂ includes a copy of the Session Key as part of its contents, and the KDC has no need to store the Session Key as it can recover a copy by decrypting theÂ TGTÂ if needed.
    

![Kerberos step 1](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d36f5a024c20fb480cdae8cd09ddc09f.png)

1. When a user wants to connect to a service on the network like a share, website or database, they will use theirÂ TGTÂ to ask the KDC for aÂ **Ticket Granting Service (TGS)**. TGS are tickets that allow connection only to the specific service they were created for. To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with theÂ TGTÂ and aÂ **Service Principal Name (SPN),**Â which indicates the service and server name we intend to access.
    
    As a result, the KDC will send us a TGS along with aÂ **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using a key derived from theÂ **Service Owner Hash**. The Service Owner is the user or machine account that the service runs under. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS.
    

![Kerberos step 2](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/84504666e78373c613d3e05d176282dc.png)

1. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.

![Kerberos step 3](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/8fbf08d03459c1b792f3b6efa4d7f285.png)

## NetNTLM Authentication

NetNTLM works using a challenge-response mechanism.Â The entire process is as follows:

![NetNTLM authentication](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2eab5cacbd0d3e9dc9afb86169b711ec.png)

1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client.
3. The client combines theirÂ NTLMÂ password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification.
4. The server forwards the challenge and the response to the Domain Controller for verification.
5. The domain controller uses the challenge to recalculate the response and compares it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server.
6. The server forwards the authentication result to the client.

Note that the user's password (or hash) is never transmitted through the network for security.

**Note:**Â The described process applies when using a domain account. If a local account is used, the server can verify the response to the challenge itself without requiring interaction with the domain controller since it has the password hash stored locally on its SAM.

![Pasted image 20250526121749.png](../../../IMAGES/Pasted%20image%2020250526121749.png)


# Trees, Forests and Trusts

----


So far, we have discussed how to manage a single domain, the role of a Domain Controller and how it joins computers, servers and users.

![Single Domain](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/69f2441bbafd4cfe57a101d87f3c5950.png)

As companies grow, so do their networks. Having a single domain for a company is good enough to start, but in time some additional needs might push you into having more than one.

## Trees

Imagine, for example, that suddenly your company expands to a new country. The new country has different laws and regulations that require you to update your GPOs to comply. In addition, you now have IT people in both countries, and each IT team needs to manage the resources that correspond to each country without interfering with the other team. While you could create a complexÂ OUÂ structure and use delegations to achieve this, having a hugeÂ ADÂ structure might be hard to manage and prone to human errors.

Luckily for us, Active Directory supports integrating multiple domains so that you can partition your network into units that can be managed independently. If you have two domains that share the same namespace (`thm.local`Â in our example), those domains can be joined into aÂ **Tree**.

If ourÂ `thm.local`Â domain was split into two subdomains for UK and US branches, you could build a tree with a root domain ofÂ `thm.local`Â and two subdomains calledÂ `uk.thm.local`Â andÂ `us.thm.local`, each with itsÂ AD, computers and users:

![Tree](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/abea24b7979676a1dcc0c568054544c8.png)

This partitioned structure gives us better control over who can access what in the domain. The IT people from the UK will have their ownÂ DCÂ that manages the UK resources only. For example, a UK user would not be able to manage US users. In that way, the Domain Administrators of each branch will have complete control over their respective DCs, but not other branches' DCs. Policies can also be configured independently for each domain in the tree.

A new security group needs to be introduced when talking about trees and forests. TheÂ **Enterprise Admins**Â group will grant a user administrative privileges over all of an enterprise's domains. Each domain would still have its Domain Admins with administrator privileges over their single domains and the Enterprise Admins who can control everything in the enterprise.  

## Forests

The domains you manage can also be configured in different namespaces. Suppose your company continues growing and eventually acquires another company calledÂ `MHT Inc.`Â When both companies merge, you will probably have different domain trees for each company, each managed by its own IT department. The union of several trees with different namespaces into the same network is known as aÂ **forest**.

![Forest](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/03448c2faf976db890118d835000bab7.png)

## Trust Relationships

Having multiple domains organised in trees and forest allows you to have a nice compartmentalised network in terms of management and resources. But at a certain point, a user atÂ THMÂ UK might need to access a shared file in one of MHT ASIA servers. For this to happen, domains arranged in trees and forests are joined together byÂ **trust relationships**.

In simple terms, having a trust relationship between domains allows you to authorise a user from domainÂ `THM UK`Â to access resources from domainÂ `MHT EU`.

The simplest trust relationship that can be established is aÂ **one-way trust relationship**. In a one-way trust, ifÂ `Domain AAA`Â trustsÂ `Domain BBB`, this means that a user on BBB can be authorised to access resources on AAA:

![Trusts](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/af95eb1a4b6c672491d8989f79c00200.png)

The direction of the one-way trust relationship is contrary to that of the access direction.

**Two-way trust relationships**Â can also be made to allow both domains to mutually authorise users from the other. By default, joining several domains under a tree or a forest will form a two-way trust relationship.

It is important to note that having a trust relationship between domains doesn't automatically grant access to all resources on other domains. Once a trust relationship is established, you have the chance to authorise users across different domains, but it's up to you what is actually authorised or not.

![Pasted image 20250526121815.png](../../../IMAGES/Pasted%20image%2020250526121815.png)

# Conclusion

---

In this room, we have shown the basic components and concepts related to Active Directories and Windows Domains. Keep in mind that this room should only serve as an introduction to the basic concepts, as there's quite a bit more to explore to implement a production-ready Active Directory environment.

If you are interested in learning how to secure an Active Directory installation, be sure to check out theÂ [Active Directory Hardening Room](https://tryhackme.com/room/activedirectoryhardening). If, on the other hand, you'd like to know how attackers can take advantage of commonÂ ADÂ misconfigurations and otherÂ ADÂ hacking techniques, theÂ [Compromising Active Directory module](https://tryhackme.com/module/hacking-active-directory)Â is the way to go.


