![Pasted image 20241222180525.png](../../IMAGES/Pasted%20image%2020241222180525.png)

_Mayor Malware laughed hard at what he had done,_

_another scheme hatched, another scheme won._ _But a thought passed the mayor, the thought then passed twice._ _The list soon to come, the town's "naughty or nice"!_

_He paced and he paced like the week of election,_ _until¦that was it! A surprise mayor inspection!_ _The list-making wares, well it only seemed fair_

_would grant him temp access, an account for the mayor. 
_

_The list makers agreed, under certain conditions._ _He logged on that day, to confirm his suspicions._

_The next day they were, when the naughty list read:_

_"Mayor Malware" Line 1, he read it with dread._

_The conditions they gave, there's something they missed._

_As somehow and someway, he accessed the list._

_Mayor Malware then smiled, as he'd find no blame._

_With this he would find, a new home for his name!_

![Pasted image 20241222180552.png](../../IMAGES/Pasted%20image%2020241222180552.png)

This is the continuation of [day 21](DAY%2021.md)

## Learning Objectives

```ad-summary
- Learn about Kubernetes, what it is and why it is used.
- Learn about DFIR, and the challenges that come with DFIR in an ephemeral environment.
- Learn how DFIR can be done in a Kubernetes environment using log analysis.
```


## Kubernetes Explained
---
Back in the day, it was very common for companies/organizations to use a monolithic architecture when building their applications. A monolithic architecture is an application built as a single unit, a single code base, and usually, a single executable deployed as a single component. For many companies, this worked and still does to this day; however, for some companies, this style of architecture was causing problems, especially when it came to scaling. The problem with monolithic applications is that if one single part of the application needs scaling, the whole application has to be scaled with it. It would make far more sense for companies with applications that receive fluctuating levels of demand across their parts to break the application down component by component and run them as their own microservices. That way, if one "microservice" starts to receive an increase in demand, it can be scaled up rather than the entire application.

**The Great Microservice Adoption**

Microservices architecture was adopted by companies like Netflix, which is a perfect example of the hypothetical company discussed above. Their need to scale up services dedicated to streaming when a new title is released (whilst services dedicated to user registration, billing, etc, won't need the same scaling level) made a microservices architecture a no-brainer. As time went by, companies similar to Netflix hopped aboard the Microservices Express, and it became very widely adopted. Now, as for the hosting of these microservices, containers were chosen due to their lightweight nature. Only as you may imagine, an application of this scale can require hundreds, even thousands of containers. Suddenly, a tool was needed to organize and manage these containers.

**Introducing Kubernetes**

Well, you guessed it! That's exactly what Kubernetes was made for. Kubernetes is a container orchestration system. Imagine one of those microservices mentioned earlier is running in a container, and suddenly, there is an increase in traffic, and this one container can no longer handle all requests. The solution to this problem is to have another container spun up for this microservice and balance the traffic between the two. Kubernetes takes care of this solution for you, "orchestrating" those containers when needed.

That makes things a lot easier for everyone involved, and it's because of this (along with the widespread adoption of microservices architecture) that Kubernetes is so ubiquitous in the digital landscape today. This popularity means that it's **highly portable** as no matter what technology stack is being used, it's very likely a Kubernetes integration is available; this, along with the fact it can help make an application **highly available** and **scalable**, makes Kubernetes a no-brainer!

In Kubernetes, containers run in **pods**; these pods run on **nodes**, and a collection of nodes makes up a Kubernetes **cluster**. It is within a cluster that McSkidy and co's investigation will occur today. If you're interested in learning more about Kubernetes, we have a range of rooms on the subject. A good place to start would be the [Intro to Kubernetes](https://tryhackme.com/r/room/introtok8s) room; then, there's plenty more where that came from with the [Kubernetes Hardening](https://tryhackme.com/module/kubernetes-hardening) Module. 

## DFIR Basics
---

Every cyber security professional has stumbled”or will stumble”upon **DFIR** at some point in their career. It is an acronym”in IT, we all _love_ our acronyms”that stands for "**Digital Forensics and Incident Response**." These two investigative branches of cyber security come into play during a cyber security incident. A DFIR expert will likely be called to action as soon as an incident is ascertained and will be expected to perform actions that fall into one or both of the two disciplines:

```ad-summary
- **Digital Forensics**, like any other "forensics" discipline, aims to collect and analyse digital evidence of an incident. The artefacts collected from the affected systems are used to trace the chain of attack and uncover all facts that ultimately led to the incident. DFIR experts sometimes use the term "post-mortem" to indicate that their analysis starts _after_ the incident has occurred and is performed on already compromised systems and networks.
- **Incident Response**, while still relying on data analysis to investigate the incident, focuses on "responsive" actions such as threat containment and system recovery. The incident responder will isolate infected machines, use the data collected during the analysis to identify the "hole" in the infrastructure's security and close it, and then recover the affected systems to a clean, previous-to-compromise state.
```

Picture the incident responder as an emergency first responder whose aim is to contain the damage, extinguish the fire, and find and stabilise all the victims. On the other hand, the digital forensics analyst is the Crime Scene Investigator (CSI) or detective trying to recreate the crime scene and ultimately find evidence to identify and frame the criminal.

Both roles are expected to document all findings thoroughly. The incident responder will present them to explain how the incident happened and what can be learnt from it, ultimately proposing changes to improve the security stance of the entity affected by the incident. The digital forensics analyst will use the findings to demonstrate the attackers' actions and”eventually”testify against them in court.

In the task at hand, we will help McSkidy and the Glitch become digital forensics analysts and retrace the malicious actor's steps. We will especially focus on collecting evidence and artefacts to uncover the perpetrator and present our analysis to Wareville townspeople.

![McSkidy and The Glitch in detective and firefighter costumes](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1730813333189.png) 

## Excruciatingly Ephemeral
---

DFIR can be a lot of fun. It's easy to feel like a digital detective, analysing the crime scene and connecting the dots to create a narrative string of events explaining what happened. What if the crime scene vanished into thin air moments after the crime was committed? That is a problem we face regularly when carrying out DFIR in a Kubernetes environment. This is because, as mentioned, Kubernetes workloads run in containers. It is **very** common that a container will have a very short lifespan (either spun up to run a job quickly or to handle increased load, etc, before being spun back down again). In fact, in this year's (2024) [Cloud-Native Security and Usage Report](https://sysdig.com/2024-cloud-native-security-and-usage-report/), Sysdig found that 70% of containers live less than 5 minutes.

So what can we do about it? Well not to worry, it just means we have to expand our digital detectives toolkit. The key to keeping track of the ongoings in your often ephemeral workloads within your Kubernetes environment is increasing **visibility**. There are a few ways we can do this. One way is by enabling Kubernetes audit logging, a function that Kubernetes provides, allowing for requests to the API to be captured at various stages. For example, if a user makes a request to delete a pod, this request can be captured, and while the pod will be deleted (and logs contained within it lost), the request made to delete it will be persisted in the audit logs. What requests/events are captured can be defined with an audit policy. We can use these audit logs to answer questions which help us in a security/DFIR context, such as:

```ad-note
- What happened?
- When did it happen?
- Who initiated it?
- To what did it happen?
- Where was it observed?
- From where was it initiated?
- To where was it going?
```

Of course, this just scratches the surface in terms of the level of visibility we can achieve in our Kubernetes environment. We can feed these audit logs, as well as events from other security-relevant sources, into runtime security tools which help transform these raw events into actionable data (which can then be visualized using yet more tools; a digital detective should definitely invest in an **extra large** toolkit). If you want to learn more on that subject, check out the [Kubernetes Runtime Security](https://tryhackme.com/r/room/k8sruntimesecurity) room.

## Following the Cookie Crumbs
---

Let's start our investigation. As mentioned before, some of the log sources would disappear as their sources, like pods, are ephemeral. Let's see this in action first. On the VM, open a terminal as start K8s using the following command:



```shell-session
ubuntu@tryhackme:~$ minikube start
minikube v1.32.0 on Ubuntu 20.04
Using the docker driver based on existing profile
Starting control plane node minikube in cluster minikube

--- removed for brevity ---

Enabled addons: storage-provisioner, default-storageclass
Done! kubectl is now configured to use "minikube" cluster and "default" namespace by default
```

It will take roughly three minutes for the cluster to configure itself and start. You can verify that the cluster is up and running using the following command:



```shell-session
ubuntu@tryhackme:~$ kubectl get pods -n wareville
NAME READY STATUS RESTARTS AGE
morality-checker 1/1 Running 8 (9m16s ago) 20d
naughty-or-nice 1/1 Running 1 (9m16s ago) 9d
naughty-picker-7cbd95dd66-gjm7r 1/1 Running 32 (9m16s ago) 20d
naughty-picker-7cbd95dd66-gshvp 1/1 Running 32 (9m16s ago) 20d
nice-picker-7cd98989c8-bfbqn 1/1 Running 32 (9m16s ago) 20d
nice-picker-7cd98989c8-ttc7t 1/1 Running 32 (9m16s ago) 20d
```

If all of the pods are up and running (based on their status), you are ready to go. This will take another **2 minutes**. Since we know that the web application was compromised, let's connect to that pod and see if we can recover any logs. Connect to the pod using the following command:



```shell-session
ubuntu@tryhackme:~$ kubectl exec -n wareville naughty-or-nice -it -- /bin/bash
root@naughty-or-nice:/#
```

Once connected, let's review the Apache2 access log:



```shell-session
root@naughty-or-nice:/# cat /var/log/apache2/access.log
172.17.0.1 - - [28/Oct/2024:11:05:45 +0000] "GET / HTTP/1.1" 200 2038 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
172.17.0.1 - - [28/Oct/2024:11:05:45 +0000] "GET /style/style.css HTTP/1.1" 200 1207 "http://localhost:8081/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"

--- removed for brevity ---

172.17.0.1 - - [29/Oct/2024:12:32:37 +0000] "GET /favicon.ico HTTP/1.1" 404 489 "http://localhost:8081/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
172.17.0.1 - - [29/Oct/2024:12:32:48 +0000] "GET /shelly.php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
```

Sadly, we only see logs from the 28th of October when our attack occurred later on. Looking at the last log, however, we do see something interesting with a request being made to a`shelly.php` file. So, this tells us we are on the right track. Terminate your session to the pod using`exit`. Fortunately, McSkidy knew that the log source was ephemeral and decided to ensure that remote backups of the log source were made. Navigate to our backup directory using`cd /home/ubuntu/dfir_artefacts/` where you will find the access logs stored in`pod_apache2_access.log`. Review these logs to see what Mayor Malware was up to on the website and answer the first 3 questions at the bottom of the task!

Sadly, our investigation hits a bit of a brick wall here. Firstly, because the pod was configured using a port forward, we don't see the actual IP that was used to connect to the instance. Also, we still don't fully understand how the webshell found its way into the pod. However, we rebooted the cluster and the webshell was present, meaning it must live within the actual image of the pod itself! That means we need to investigate the docker image registry itself. To view the registry container ID, run the following command:


```shell-session
ubuntu@tryhackme:~$ docker ps
CONTAINER ID IMAGE COMMAND --- removed for brevity ---
77fddf1ff1b8 registry:2.7 "/entrypoint.sh /etc¦" --- removed for brevity ---
cd9ee77b8aa5 gcr.io/k8s-minikube/kicbase:v0.0.42 --- removed for brevity ---
```

Now, let's connect to the instance to see if we have any logs:


```shell-session
ubuntu@tryhackme:~$ docker exec -it <registry:2.7 container ID> ls -al /var/log
total 12
drwxr-xr-x 2 root root 4096 Nov 12 2021 .
drwxr-xr-x 1 root root 4096 Nov 12 2021 ..
```

Again, we hit a wall since we don't have any registry logs. Luckily, docker itself would keep logs for us. Let's pull these logs using the following:



```shell-session
ubuntu@tryhackme:~$ docker logs <registry:2.7 container ID> 
172.17.0.1 - - [16/Oct/2024:09:02:39 +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/26.0.0 go/go1.21.8 git-commit/8b79278 kernel/5.15.0-1070-aws os/linux arch/amd64 UpstreamClient(Docker-Client/26.0.0 \\(linux\\))"
172.17.0.1 - - [16/Oct/2024:09:02:39 +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/26.0.0 go/go1.21.8 git-commit/8b79278 kernel/5.15.0-1070-aws os/linux arch/amd64 UpstreamClient(Docker-Client/26.0.0 \\(linux\\))"

--- removed for brevity ---

time="2024-11-08T04:32:42.87960937Z" level=info msg="using inmemory blob descriptor cache" go.version=go1.11.2 instance.id=ef35cf6e-fd01-4041-abba-2c082fd682f0 service=registry version=v2.7.1 
time="2024-11-08T04:32:42.880803524Z" level=info msg="listening on [::]:5000" go.version=go1.11.2 instance.id=ef35cf6e-fd01-4041-abba-2c082fd682f0 service=registry version=v2.7.1
```

Now we have something we can use! These logs have been pulled for you and are stored in the`/home/ubuntu/dfir_artefacts/docker-registry-logs.log` file. Let's start by seeing all the different connections that were made to the registry by searching for the HEAD HTTP request code and restricting it down to only the first item, which is the IP:


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat docker-registry-logs.log | grep "HEAD" | cut -d ' ' -f 1
172.17.0.1
172.17.0.1
172.17.0.1

--- removed for brevity ---

10.10.130.253
10.10.130.253
10.10.130.253
```

Here we can see that most of the connections to our registry was made from the expected IP of 172.17.0.1, however, we can see that connections were also made by 10.10.130.253, which is not an IP known to us. Let's find all of the requests made by this IP:


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat docker-registry-logs.log | grep "10.10.130.253"
10.10.130.253 - - [29/Oct/2024:10:06:33 +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
10.10.130.253 - - [29/Oct/2024:10:06:33 +0000] "GET /v2/ HTTP/1.1" 200 2 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"

--- removed for brevity ---

10.10.130.253 - - [29/Oct/2024:12:34:31 +0000] "PUT /v2/wishlistweb/manifests/latest HTTP/1.1" 201 0 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
```

Now, we are getting somewhere. If we review the first few requests, we can see that several authentication attempts were made. But, we can also see that the request to read the manifest for the wishlistweb image succeeded, as the HTTP status code of 200 is returned in this log entry:

`10.10.130.253 - - [29/Oct/2024:12:26:40 +0000] "GET /v2/wishlistweb/manifests/latest HTTP/1.1" 200 6366 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"`

What we also notice is the User Agent in the request is docker, meaning this was a request made through the docker CLI to pull the image. This is confirmed as we see several requests then to download the image. From this, we learn several things:

- The docker CLI application was used to connect to the registry.
- Connections came from 10.10.130.253, which is unexpected since we only upload images from 172.17.0.1.
- The client was authenticated, which allowed the image to be pulled. This means that whoever made the request had access to credentials.

If they had access to credentials to pull an image, the same credentials might have allowed them to also push a new image. We can verify this by narrowing our search to any PATCH HTTP methods. The PATCH method is used to update docker images in a registry:


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat docker-registry-logs.log | grep "10.10.130.253" | grep "PATCH"
10.10.130.253 - - [29/Oct/2024:12:34:28 +0000] "PATCH /v2/wishlistweb/blobs/uploads/2966 --- removed for brevity ---
10.10.130.253 - - [29/Oct/2024:12:34:31 +0000] "PATCH /v2/wishlistweb/blobs/uploads/7d53 --- removed for brevity ---
```

This is not good! It means that Mayor Malware could push a new version of our image! This would explain how the webshell made its way into the image, since Mayor Malware pulled the image, made malicious updates, and then pushed this compromised image back to the registry! Use the information to answer questions 4 through 6 at the bottom of the task. Now that we know Mayor Malware had access to the credentials of the docker registry, we need to learn how he could have gained access to them. We use these credentials in our Kubernetes cluster to read the image from the registry, so let's see what could have happened to disclose them!

Okay, so it looks like the attack happened via an authenticated docker registry push. Now, it's time to turn to our Kubernetes environment and determine how this was possible. McSkidy was made aware that Mayor Malware was given user access to the naughty or nice Kubernetes environment but was assured by the DevSecOps team that he wouldn't have sufficient permissions to view secrets, etc. The first thing we should do is make sure this is the case. To do this, McSkidy decides to check what role was assigned to the mayor. She first checks the rolebindings (binds a role to a user):



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ kubectl get rolebindings -n wareville
NAME ROLE AGE
job-runner-binding Role/job-runner 20d
mayor-user-binding Role/mayor-user 20d
```

McSkidy then sees a rolebinding named after Mayor Malware and decides to take a closer look:


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ kubectl describe rolebinding mayor-user-binding -n wareville
Name: mayor-user-binding
Labels: <none>
Annotations: <none>
Role:
 Kind: Role
 Name: mayor-user
Subjects:
 Kind Name Namespace
 ---- ---- ---------
 User mayor-malware
```

From the output, she could see that there is a role "mayor-user" that is bound to the user "mayor-malware". McSkidy then checked this role to see what permissions it has (and therefore Mayor Malware had):```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ kubectl describe role mayor-user -n wareville
Name: mayor-user
Labels: <none>
Annotations: <none>
PolicyRule:
 Resources Non-Resource URLs Resource Names Verbs
 --------- ----------------- -------------- -----
 pods/exec [] [] [create get list]
 rolebindings.rbac.authorization.k8s.io [] [] [get list describe]
 roles.rbac.authorization.k8s.io [] [] [get list describe]
 pods [] [] [get list watch]
```

The output here tells McSkidy something very important. A lot of the permissions listed here are as you would expect for a non-admin user in a Kubernetes environment, all of those except for the permissions associated with "pods/exec". Exec allows the user to shell into the containers running within a pod. This gives McSkidy an idea of what Mayor Malware might have done. To confirm her suspicious, she checks the audit logs for Mayor Malware's activity:`cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'` 

This returns a lot of logs, let's go through them as Mcskidy starts to form the attack path taken by Mayor Malware:

**Get Secrets**


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'
--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"a02486f1-3a7c-4bca-8bcb-9019fa43dac4","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/wareville/secrets?limit=500","verb":"list","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"secrets","namespace":"wareville","apiVersion":"v1"},"responseStatus":{"metadata":{},"status":"Failure","message":"secrets is forbidden: User \"mayor-malware\" cannot list resource \"secrets\" in API group \"\" in the namespace \"wareville\"","reason":"Forbidden","details":{"kind":"secrets"},"code":403},"responseObject":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"secrets is forbidden: User \"mayor-malware\" cannot list resource \"secrets\" in API group \"\" in the namespace \"wareville\"","reason":"Forbidden","details":{"kind":"secrets"},"code":403},"requestReceivedTimestamp":"2024-10-29T12:20:30.664633Z","stageTimestamp":"2024-10-29T12:20:30.666165Z","annotations":{"authorization.k8s.io/decision":"forbid","authorization.k8s.io/reason":""}

--- removed for brevity ---
```

This log snippet tells us that Mayor Malware attempted to get the secrets stored on the cluster but received a 403 response as he didn't have sufficient permissions to do so (Note: a plural get command runs a list on the backend, and is why it appears as so in the logs).

**Get Roles**

 

```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"8084daec-f59f-4d90-b343-f59f4f3cd67c","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/namespaces/wareville/roles?limit=500","verb":"list","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"roles","namespace":"wareville","apiGroup":"rbac.authorization.k8s.io","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:20:39.761026Z","stageTimestamp":"2024-10-29T12:20:39.762868Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

After being denied secret access, Mayor Malware then started snooping to see what roles were present on the cluster.

**Describe Role**


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"6ef973f4-82ab-4326-b66b-24d7036cae64","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/namespaces/wareville/roles/job-runner","verb":"get","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"roles","namespace":"wareville","name":"job-runner","apiGroup":"rbac.authorization.k8s.io","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:20:49.497325Z","stageTimestamp":"2024-10-29T12:20:49.498588Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

Whilst running the previous "get roles" command, Mayor Malware will have found a role named "job-runner". These logs tell us that Mayor Malware then described this role, which would have given him key pieces of information regarding the role. Most importantly for our investigation, it would have told him this role has secret read access. **Get Rolebindings**


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"25b7417e-550c-4b9a-bb2c-dad64662cce0","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/namespaces/wareville/rolebindings?limit=500","verb":"list","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"rolebindings","namespace":"wareville","apiGroup":"rbac.authorization.k8s.io","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:20:59.570824Z","stageTimestamp":"2024-10-29T12:20:59.575620Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

Now, knowing this role can view secrets, Major Malware tried to find its role binding to see what was using this role.

 

**Describe Rolebinding**



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"b0f9aa98-9039-4df8-b990-9bf6ca48ab2f","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/namespaces/wareville/rolebindings/job-runner-binding","verb":"get","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"rolebindings","namespace":"wareville","name":"job-runner-binding","apiGroup":"rbac.authorization.k8s.io","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:21:11.521236Z","stageTimestamp":"2024-10-29T12:21:11.523301Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

After seeing a role binding named "job-runner-binding", Mayor Malware described it and found out this role is bound to a service account named "job-runner-sa" (aka this service account has permission to view secrets)

 
**Get Pods**

```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"9d13a9b6-78d2-4cfc-8dc5-889b83aafc44","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/wareville/pods?limit=500","verb":"list","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"pods","namespace":"wareville","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:21:22.660584Z","stageTimestamp":"2024-10-29T12:21:22.664112Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

Here, we can see that Mayor Malware, now armed with the knowledge that a service account has the permissions he needs, lists all of the pods running in the Wareville namespace with a kubectl get pods command.

 

**Describe Pod**



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"5965471b-4fb9-49c9-9a16-7fd466c762c8","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/wareville/pods/morality-checker","verb":"get","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"pods","namespace":"wareville","name":"morality-checker","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2024-10-29T12:21:33.182365Z","stageTimestamp":"2024-10-29T12:21:33.185006Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

Mayor Malware describes the pod as a "morality-checker" he then would have found out that this pod runs with the job-runner-sa service account attached. Meaning that if he were able to gain access to this pod, he would be able to gain secret read access.

 

**Exec**



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"mayor-malware"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"927fcde7-74e5-4a57-af53-dceacefaf47c","stage":"ResponseStarted","requestURI":"/api/v1/namespaces/wareville/pods/morality-checker/exec?command=%2Fbin%2Fsh\u0026container=kubectl-container\u0026stdin=true\u0026stdout=true\u0026tty=true","verb":"create","user":{"username":"mayor-malware","groups":["example","system:authenticated"]},"sourceIPs":["192.168.49.1"],"userAgent":"kubectl/v1.29.3 (linux/amd64) kubernetes/6813625","objectRef":{"resource":"pods","namespace":"wareville","name":"morality-checker","apiVersion":"v1","subresource":"exec"},"responseStatus":{"metadata":{},"code":101},"requestReceivedTimestamp":"2024-10-29T12:21:44.189258Z","stageTimestamp":"2024-10-29T12:21:44.214173Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"mayor-user-binding/wareville\" of Role \"mayor-user\" to User \"mayor-malware\""}}

--- removed for brevity ---
```

As mentioned in the role discussion, exec is permission usually not included in a non-admin role. It is for this exact reason that this is the case; McSkidy feels confident that the DevSecOps team had overly permissive Role-Based Access Control (RBAC) in place in the Kubernetes environment, and it was this that allowed Mayor Malware to run an exec command (as captured by the logs above) and gain shell access into morality-checker. To confirm her suspicions further, McSkidy runs the following command to retrieve audit logs captured from the job-runner-sa service account:



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"system:serviceaccount:wareville:job-runner-sa"' | grep --color=always '"resource"' | grep --color=always '"verb"'
```

Here we can see a few commands being run. We can see Mayor Malware is able to now run "get" commands on secrets to list them, but most importantly, we can see he has indeed been able to escalate his privileges and gain access to the "pull-creds" secret using the job-runner-sa service account:



```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ cat audit.log | grep --color=always '"user":{"username":"system:serviceaccount:wareville:job-runner-sa"' | grep --color=always '"resource"' | grep --color=always '"verb"'

--- removed for brevity ---

{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"c59d6a7c-1e07-43cb-8bf6-4d41a9c98ddb","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/wareville/secrets/pull-creds","verb":"get","user":{"username":"system:serviceaccount:wareville:job-runner-sa","uid":"9e88bb94-e5e3-4e13-9187-4eaf898d0a7e","groups":["system:serviceaccounts","system:serviceaccounts:wareville","system:authenticated"],"extra":{"authentication.kubernetes.io/pod-name":["morality-checker"],"authentication.kubernetes.io/pod-uid":["a20761b8-1a36-4318-a048-96d61644b436"]}},"sourceIPs":["10.244.120.126"],"userAgent":"kubectl/v1.31.1 (linux/amd64) kubernetes/948afe5","objectRef":{"resource":"secrets","namespace":"wareville","name":"pull-creds","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"responseObject":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"pull-creds","namespace":"wareville","uid":"c3854acc-f67b-4e82-a975-816e0c6ab04b","resourceVersion":"174795","creationTimestamp":"2024-10-17T18:10:27Z","managedFields":[{"manager":"kubectl-create","operation":"Update","apiVersion":"v1","time":"2024-10-17T18:10:27Z","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:.dockerconfigjson":{}},"f:type":{}}}]},"data":{".dockerconfigjson":"eyJhdXRocyI6eyJodHRwOi8vZG9ja2VyLXJlZ2lzdHJ5Lm5pY2V0b3duLmxvYzo1MDAwIjp7InVzZXJuYW1lIjoibXIubmljZSIsInBhc3N3b3JkIjoiTXIuTjR1Z2h0eSIsImF1dGgiOiJiWEl1Ym1salpUcE5jaTVPTkhWbmFIUjUifX19"},"type":"kubernetes.io/dockerconfigjson"},"requestReceivedTimestamp":"2024-10-29T12:22:15.861424Z","stageTimestamp":"2024-10-29T12:22:15.864166Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"job-runner-binding/wareville\" of Role \"job-runner\" to ServiceAccount \"job-runner-sa/wareville\""}}

--- removed for brevity ---
```

The final piece of the puzzle revolved around this secret. Finally, she runs the command, and the attack path is confirmed:


```shell-session
ubuntu@tryhackme:~/dfir_artefacts$ kubectl get secret pull-creds -n wareville -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode
```

Shaking her head, McSkidy then confirms that the docker registry pull password is the same as the push password. This means that after retrieving these credentials, Mayor Malware would have been able to make the docker registry push we saw earlier and ensure his malicious web shell was deployed into the Kubernetes environment and gain persistence. It is for this reason that push and pull credentials should always be different. With that, the investigation is all tied up, the conclusion being that Mayor Malware most certainly belongs on the naughty list this year!

## Questions
---

![Pasted image 20241222181730.png](../../IMAGES/Pasted%20image%2020241222181730.png)

To get the review of each answer, watch this video, didn't have much time since I was sick.

Just like that, day 22 is done!

<iframe width="900" height="690" src="https://www.youtube.com/embed/8LP9akZaJzU" title="Kubernetes DFIR (Digital Forensics &amp; Incident Response) - Day 22 of TryHackMe Advent of Cyber 2024" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

