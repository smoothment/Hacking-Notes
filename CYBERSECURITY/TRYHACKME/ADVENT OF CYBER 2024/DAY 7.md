The Story

![Task banner for day 7.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730384938554.png)

_As SOC-mas approached, so did the need,_

_To provide those without, with something to read._

_Care4Wares tried, they made it their mission,_

_A gift for all wares, a SOC-mas tradition._

_Although they had some, they still needed more,_

_To pick up some books, they'd head to the store._

_The town's favourite books, would no doubt make them jolly,_

_They ticked off the list, as they filled up the trolley._

_With the last book ticked off, the shopping was done,_

_When asked for their card, the ware handed them one._

_I'm sorry he said, as the shop clerk reclined,_

_I can't sell you these books, as your card has declined._

_The ware put them back, as they walked in confusion,_ _How could this be? An attack? An intrusion?_ _And when they logged on, the ware got a scare,_

_To find the donations, they just weren't there!_

![ware buying books image](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1731078051718.png)

This is the continuation of [day 6](DAY%206.md)
## Monitoring in an AWS Environment
---
Care4Wares' infrastructure runs in the cloud, so they chose AWS as their Cloud Service Provider (CSP). Instead of their workloads running on physical machines on-premises, they run on virtualized instances in the cloud. These instances are (in AWS) called EC2 instances (Amazon Elastic Compute Cloud). A few members of the Wareville SOC aren't used to log analysis on the cloud, and with a change of environment comes a change of tools and services needed to perform their duties. Their duties this time are to help Care4Wares figure out what has happened to the charity's funds; to do so, they will need to learn about an AWS service called CloudWatch.

**CloudWatch**

AWS CloudWatch is a monitoring and observability platform that gives us greater insight into our AWS environment by monitoring applications at multiple levels. CloudWatch provides functionalities such as the monitoring of system and application metrics and the configuration of alarms on those metrics for the purposes of today's investigation, though we want to focus specifically on CloudWatch logs. Running an application in a cloud environment can mean leveraging lots of different services (e.g. a service running the application, a service running functions triggered by that application, a service running the application backend, etc.); this translates to logs being generated from lots of different sources. CloudWatch logs make it easy for users to access, monitor and store the logs from all these various sources. A CloudWatch agent must be installed on the appropriate instance for application and system metrics to be captured.

A key feature of CloudWatch logs that will help the Warevile SOC squad and us make sense of what happened in their environment is the ability to query application logs using filter patterns. Here are some CloudWatch terms you should know before going further:

```ad-important
- **Log Events:** A log event is a single log entry recording an application "event"; these will be timestamped and packaged with log messages and metadata.
- **Log Streams:** Log streams are a collection of log events from a single source.
- **Log Groups:** Log groups are a collection of log streams. Log streams are collected into a log group when logically it makes sense, for example, if the same service is running across multiple hosts.
```

**CloudTrail**

CloudWatch can track infrastructure and application performance, but what if you wanted to monitor actions in your AWS environment? These would be tracked using another service called AWS CloudTrail. Actions can be those taken by a user, a role (granted to a user giving them certain permissions) or an AWS service and are recorded as events in AWS CloudTrail. Essentially, any action the user takes (via the management console or AWS CLI) or service will be captured and stored. Some features of CloudTrail include:

```ad-info
- **Always On:** CloudTrail is enabled by default for all users
- **JSON-formatted:** All event types captured by CloudTrail will be in the CloudTrail JSON format
- **Event History:** When users access CloudTrail, they will see an option "Event History", event history is a record of the actions that have taken place in the last 90 days. These records are queryable and can be filtered on attributes such as "resource" type.
- **Trails:** The above-mentioned event history can be thought of as the default "trail," included out of the box. However, users can define custom trails to capture specific actions, which is useful if you have bespoke monitoring scenarios you want to capture and store **beyond the 90-day event history retention period**.
- **Deliverable:** As mentioned, CloudWatch can be used as a single access point for logs generated from various sources; CloudTrail is no different and has an optional feature enabling **CloudTrail logs to be delivered to CloudWatch**.
```

![JSON rain image](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1731078142249.png) 

As mentioned, CloudTrail helps capture and record actions taken. These actions could be interactions with any number of AWS services. For example, services like **S3** (Amazon Simple Storage Service used for object storage) and **IAM** (AWS's Identity and Access Management service can be used to secure access to your AWS environment with the creation of identities and the assigning of access permissions to those identities) will have actions taken within their service recorded. These recorded events can be very helpful when performing an investigation. 

## Intro to JQ
----
**What is JQ?**

Earlier, it was mentioned that Cloudtrail logs were JSON-formatted. When ingested in large volumes, this machine-readable format can be tricky to extract meaning from, especially in the context of log analysis. The need then arises for something to help us transform and filter that JSON data into meaningful data we can understand and use to gain security insights. That's exactly what JQ is (and does!). Similar to command line tools like sed, awk and grep, JQ is a lightweight and flexible command line processor that can be used on JSON.

![Cloud JQ investigation image](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1731078090249.png)

**How Can It Be Used?**

Now, let's take a look at how we use JQ to transform and filter JSON data. The wares being the wares, they stored their shopping list from the trip to the bookstore in JSON format. Let's take a look at that:

```javascript
[

{ "book_title": "Wares Wally", "genre": "children", "page_count": 20 },

{ "book_title": "Charlottes Web Crawler", "genre": "young_ware", "page_count": 120 },

{ "book_title": "Charlie and the 8 Bit Factory", "genre": "young_ware", "page_count": 108 },

{ "book_title": "The Princess and the Pcap", "genre": "children", "page_count": 48 },

{ "book_title": "The Lion, the Glitch and the Wardrobe", "genre": "young_ware", "page_count": 218 }

]
```

JQ takes two inputs: the filter you want to use, followed by the input file. We start our JQ filter with a`.` which just tells JQ we are accessing the current input. From here, we want to access the array of values stored in our JSON (with the`[]`). Making our filter a`.[]`. For example, let's run the following command.


```shell-session
user@tryhackme$ jq '.[]' book_list.json
```

The command above would result in this output:

```javascript
{
 "book_title": "Wares Wally",
 "genre": "children",
 "page_count": 20
}
{
 "book_title": "Charlottes Web Crawler",
 "genre": "young_ware",
 "page_count": 120
}
{
 "book_title": "Charlie and the 8 Bit Factory",
 "genre": "young_ware",
 "page_count": 108
}
{
 "book_title": "The Princess and the Pcap",
 "genre": "children",
 "page_count": 48
}
{
 "book_title": "The Lion, the Glitch and the Wardrobe",
 "genre": "young_ware",
 "page_count": 218
}
```

Once we've accessed the array, we can grab elements from that array by going one step deeper. For example, we could run this JQ command:


```shell-session
user@tryhackme$ jq '.[] | .book_title' book_list.json
```

If we wanted to view all the book titles contained within this JSON file, this would return a nicely formatted output like this:

```javascript
"Wares Wally"
"Charlottes Web Crawler"
"Charlie and the 8 Bit Factory"
"The Princess and the Pcap"
"The Lion, the Glitch and the Wardrobe"
```

That's a lot nicer to look at, isn't it? It gives you an idea of what JQ is and what it does. Of course, JQ can filter and transform JSON data in many additional ways. In our upcoming investigation, we'll see the tool in action.


## The Peculiar Case of Care4Wares' Dry Funds
---
Now that we have refreshed our knowledge of AWS Cloudtrail and JQ alongside McSkidy, let's investigate this peculiar case of Care4Wares' dry funds.

The responsible ware for the Care4Wares charity drive gave us the following info regarding this incident:

_We sent out a link on the 28th of November to everyone in our network that points to a flyer with the details of our charity. The details include the account number to receive donations. We received many donations the first day after sending out the link, but there were none from the second day on. I talked to multiple people who claimed to have donated a respectable sum. One showed his transaction, and I noticed the account number was wrong. I checked the link, and it was still the same. I opened the link, and the digital flyer was the same except for the account number._

McSkidy recalls putting the digital flyer, **wareville-bank-account-qr.png**, in an Amazon AWS S3 bucket named **wareville-care4wares**. Let's assist McSkidy and start by finding out more about that link. Before that, let's first review the information that we currently have to start the investigation:

```ad-info
- The day after the link was sent out, several donations were received.
- Since the second day after sending the link, no more donations have been received.
- A donator has shown proof of his transaction. It was made 3 days after he received the link. The account number in the transaction was not correct.
- McSkidy put the digital flyer in the AWS S3 object named **wareville-bank-account-qr.png** under the bucket **wareville-care4wares**.
- The link has not been altered.
```
## Glitch Did It
---
Let's examine the Cloudtrail logs related to the **wareville-care4wares** S3 bucket. For a quick example, a typical S3 log entry looks like this:

```json
{
 "eventVersion": "1.10",
 "userIdentity": {
 "type": "IAMUser",
 "principalId": "AIDAXRMKYT5O5Y2GLD4ZG",
 "arn": "arn:aws:iam::518371450717:user/wareville_collector",
 "accountId": "518371450717",
 "accessKeyId": "AKIAXRMKYT5OZCZPGNZ7",
 "userName": "wareville_collector"
 },
 "eventTime": "2024-10-21T22:13:24Z",
 "eventSource": "s3.amazonaws.com",
 "eventName": "ListObjects",
 "awsRegion": "ap-southeast-1",
 "sourceIPAddress": "34.247.218.56",
 "userAgent": "[aws-sdk-go/0.24.0 (go1.22.6; linux; amd64)]",
 "requestParameters": {
 "bucketName": "aoc-cloudtrail-wareville",
 "Host": "aoc-cloudtrail-wareville.s3.ap-southeast-1.amazonaws.com",
 "prefix": ""
 },
 "responseElements": null,
 "additionalEventData": {
 "SignatureVersion": "SigV4",
 "CipherSuite": "TLS_AES_128_GCM_SHA256",
 "bytesTransferredIn": 0,
 "AuthenticationMethod": "AuthHeader",
 "x-amz-id-2": "yqniVtqBrL0jNyGlvnYeR3BvJJPlXdgxvjAwwWhTt9dLMbhgZugkhlH8H21Oo5kNLiq8vg5vLoj3BNl9LPEAqN5iHpKpZ1hVynQi7qrIDk0=",
 "bytesTransferredOut": 236375
 },
 "requestID": "YKEKJP7QX32B4NZB",
 "eventID": "fd80529f-d0af-4f44-8034-743d8d92bdcf",
 "readOnly": true,
 "resources": [
 {
 "type": "AWS::S3::Object",
 "ARNPrefix": "arn:aws:s3:::aoc-cloudtrail-wareville/"
 },
 {
 "accountId": "518371450717",
 "type": "AWS::S3::Bucket",
 "ARN": "arn:aws:s3:::aoc-cloudtrail-wareville"
 }
 ],
 "eventType": "AwsApiCall",
 "managementEvent": false,
 "recipientAccountId": "518371450717",
 "eventCategory": "Data",
 "tlsDetails": {
 "tlsVersion": "TLSv1.3",
 "cipherSuite": "TLS_AES_128_GCM_SHA256",
 "clientProvidedHostHeader": "aoc-cloudtrail-wareville.s3.ap-southeast-1.amazonaws.com"
 }
}
```


It might be overwhelming to see the sheer amount of information in one event, but there are some elements that we can focus on for our investigation:

| | |
| ----------------- | ------------------------------------------------------------------------------------ |
| **Field** | **Description** |
| userIdentity | Details of the user account that acted on an object. |
| eventTime | When did the action occur? |
| eventType | What type of event occurred? (e.g., AwsApiCall or AwsConsoleSignIn, AwsServiceEvent) |
| eventSource | From what service was the event logged? |
| eventName | What specific action occurred? (e.g., ListObjects, GetBucketObject) |
| sourceIPAddress | From what IP did the action happen? |
| userAgent | What user agent was used to perform the action? (e.g., Firefox, AWS CLI) |
| requestParameters | What parameters were involved in the action? (e.g., BucketName) |

By using the guide above, we can read the example log entry as follows: - The IAM user, **wareville_collector**, listed all objects (ListObjects event) of the S3 bucket named **aoc-cloudtrail-wareville**.
- The IP address from which this request originated is **34.247.218.56**.
- The user agent indicates that the request was made using the **AWS SDK tool for Go**.

Now that we know where to look, let's use JQ to filter the log for events related to the **wareville-bank-account-qr.png** S3 object. The goal is to use the same elements to filter the log file using JQ and format the results into a table to make it more readable. According to McSkidy, the logs are stored in the`~/wareville_logs` directory.

To start, click the **Terminal** icon on the Desktop and enter the two commands below:


```shell-session
ubuntu@tryhackme:~/$ cd wareville_logs
ubuntu@tryhackme:~/$ ls
cloudtrail_log.json rds.log
```


With the commands above, we initially changed our current directory to the directory McSkidy mentioned via the`cd` command, and we listed the directory's contents using the`ls` command. As you can see, two files are inside it, but we will focus first on the **cloudtrail_log.json** for this investigation. Now, let's start investigating the CloudTrail logs by executing the command below.


ubuntu@tryhackme:~/wareville_logs

```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares")' cloudtrail_log.json
```

Let's do a quick breakdown of the command we executed:

| Command | Description |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `jq -r 'FILTER' cloudtrail_log.json` | - The **-r** flag tells **jq** to output the results in RAW format instead of JSON. <br>- Note that the **FILTER** section is enclosed with single quotes.<br>- The last part of the command accepts the input file, which is **cloudtrail_log.json**. |
| `.Records[]` | - Instructs **jq** to parse the events in the Records container element. The **Records** field is the top element in the JSON-formatted CloudTrail log. |
| `\| select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares")` | - Uses the previous command's output, and filters it on the **eventSource** and **requestParameters.bucketName** keys.<br>- The value **s3.amazonaws.com** is used to filter events related to the Amazon AWS S3 service, and the value **wareville-care4wares** is used to filter events related to the target S3 bucket. |


As you can see in the command output, we were able to trim down the results since all of the entries are from S3. However, it is still a bit overwhelming since all the fields are included in the output. Now, let's refine the output by selecting the significant fields. Execute the following command below:

```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]' cloudtrail_log.json
```


As you can see, we have appended another pipe (`|`) after our previous filter. Let's discuss it quickly:

| Command | Description |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `\| [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"])'` | - The piped filter uses the previous command's output and formats it to only include the defined keys, such as **.eventTime**, **.eventName**, and **.userIdentity.userName**.<br>- The defined keys are enclosed with square brackets (`[]`) **to process and create an array with the specified fields from each record**.<br>- Note that the string`// "N/A"` is included purely for formatting reasons. This means that if the defined key does not have a value, it will display **N/A** instead. |


As you can see in the results, we could focus on the notable items, but our initial goal is to render the output in a table to make it easy to digest. Let's upgrade our command with additional parameters.


```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq -r '["Event_Time", "Event_Name", "User_Name", "Bucket_Name", "Key", "Source_IP"],(.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t
```

You may observe that we have added the following items to our command:

| Command | Description |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `jq -r '["Event_Time", "Event_Name", "User_Name", "Bucket_Name", "Key", "Source_IP"], SELECT_FILTER \| SPECIFIC FIELDS'` | - The new command prepends a column header row and is defined using square brackets since it is an array that corresponds to the selected fields.<br>- Note that a comma is used before the select filter to combine with those of the select filter results we previously used. |
| `\| @tsv'` | - Sets each array element, the output processed after the filters, as a line of tab-separated values. |
| `\| column -t -s $'\t'` | - It takes the output of the **jq** command, now resulting in tab-separated values, and beautifies its result by processing all tabs and aligning the columns. |


**Note:** Our crafted command lets us summarise S3 activities from a CloudTrail log.

Now that we have crafted a JQ query that provides a well-refined output, let's look at the results and observe the events. Based on the columns, we can answer the following questions to build our assumptions:

```ad-summary
- How many log entries are related to the **wareville-care4wares** bucket?
- Which user initiated most of these log entries?
- Which actions did the user perform based on the **eventName** field?
- Were there any specific files edited?
- What is the timestamp of the log entries?
- What is the source IP related to these log entries?
```


Looking at the results, 5 logged events seem related to the **wareville-care4wares** bucket, and almost all are related to the user glitch. Aside from listing the objects inside the bucket (ListOBject event), the most notable detail is that the user glitch uploaded the file **wareville-bank-account-qr.png** on November 28th. This seems to coincide with the information we received about no donations being made 2 days after the link was sent out.

McSkidy is sure there was no user glitch in the system before. There is no one in the city hall with that name, either. The only person that McSkidy knows with that name is the hacker who keeps to himself. McSkidy suggests that we look into this anomalous user.

## McSkidy Fooled Us?
---

McSkidy wants to know what this anomalous user account has been used for, when it was created, and who created it. Enter the command below to see all the events related to the anomalous user. We can focus our analysis on the following questions:

```ad-summary
- What event types are included in these log entries?
- What is the timestamp of these log entries?
- Which IPs are included in these log entries?
- What tool/OS was used in these log entries?
```

The results show that the user glitch mostly targeted the S3 bucket. The notable event is the **ConsoleLogin** entry, which tells us that the account was used to access the AWS Management Console using a browser.

We still need information about which tool and OS were used in the requests. Let's view the **userAgent** value related to these events using the following command.

There are two **User-Agent** values included in all log entries related to the **glitch** user: | Command | Description |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-192.879.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard` | - This is the userAgent string for the internal console used in AWS. It doesn't provide much information. |
| `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36` | - This userAgent string provides us with 2 pieces of interesting information.<br>- The anomalous account uses a Google Chrome browser within a Mac OS system. |


An experienced attacker can forge these values, but we should not dismiss this information. It can be valuable when comparing different log entries for the same user. We will park the current information for now, let's gather more information to connect the dots.

The next interesting event to look for is who created this anomalous user account. We will filter for all IAM-related events, and this can be done by using the select filter`.eventSource == "iam.amazonaws.com"`. Let's execute the command below, and try to answer the following questions:

```ad-summary
- What Event Names are included in the log entries?
- What user executed these events?
- What is this user's IP?
```

Based on the results, there are many ListPolicies events. By ignoring these events, it seems that the most significant IAM activity is about the user **mcskidy** invoking the **CreateUser** action and consequently invoking the **AttachUserPolicy** action. The source IP where the requests were made is **53.94.201.69**. Remember that it is the same IP the anomalous user glitch used.

Let's have a more detailed look at the event related to the **CreateUser** action by executing the command below:


```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq '.Records[] |select(.eventSource=="iam.amazonaws.com" and .eventName== "CreateUser")' cloudtrail_log.json
```

Based on the request parameters of the output, it can be seen that it was the user, **mcskidy**, who created the anomalous account.

Now, we need to know what permissions the anomalous user has. It could be devastating if it has access to our whole environment. We need to filter for the **AttachUserPolicy** event to uncover the permissions set for the newly created user. This event applies access policies to users, defining the extent of access to the account. Let's filter for the specific event by executing the command below.


```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq '.Records[] | select(.eventSource=="iam.amazonaws.com" and .eventName== "AttachUserPolicy")' cloudtrail_log.json
```

McSkidy is baffled by these results. She knows that she did not create the anomalous user and did not assign the privileged access. She also doesn't recognize the IP address involved in the events and does not use a Mac OS; she only uses a Windows machine. All this information is different to the typical IP address and machine used by McSkidy, so she wants to prove her innocence and asks to continue the investigation.

## Logs Don't Lie
----

McSkidy suggests looking closely at the IP address and operating system related to all these anomalous events. Let's use the following command below to continue with the investigation:

```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], (.Records[] | select(.sourceIPAddress=="53.94.201.69") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

Based on the command output, three user accounts (**mcskidy**, **glitch**, and **mayor_malware**) were accessed from the same IP address. The next step is to check each user and see if they always work from that IP.

Let's focus on each user and see if they always work from that IP. Enter the command below, and replace the`PLACEHOLDER` with the username.

```shell-session
ubuntu@tryhackme:~/wareville_logs$ jq -r '["Event_Time","Event_Source","Event_Name", "User_Name","User_Agent","Source_IP"],(.Records[] | select(.userIdentity.userName=="PLACEHOLDER") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A",.userAgent // "N/A",.sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

While gathering the information for each user, we can focus our investigation on the following questions:

```ad-summary
- Which IP does each user typically use to log into AWS?
- Which OS and browser does each user usually use?
- Are there any similarities or explicit differences between the IP addresses and operating systems used?
```

Based on the results, we have proven that McSkidy used a different IP address before the unusual authentication was discovered. Moreover, all evidence seems to point towards another user after correlating the IP address and User-Agent used by each user. Who do you think it could be? McSkidy has processed all the investigation results and summarized them below:

```ad-summary
- The incident starts with an anomalous login with the user account **mcskidy** from IP **53.94.201.69**.
- Shortly after the login, an anomalous user account **glitch** was created.
- Then, the **glitch** user account was assigned administrator permissions.
- The **glitch** user account then accessed the S3 bucket named **wareville-care4wares** and replaced the **wareville-bank-account-qr.png** file with a new one. The IP address and User-Agent used to log into the **glitch, mcskidy**, and **mayor_malware** accounts were the same.
- the User-Agent string and Source IP of recurrent logins by the user account **mcskidy** are different.
```

## Definite Evidence
---

McSkidy suggests gathering stronger proof that that person was behind this incident. Luckily, Wareville Bank cooperated with us and provided their database logs from their Amazon Relational Database Service (RDS). They also mentioned that these are captured through their CloudWatch, which differs from the CloudTrail logs as they are not stored in JSON format. For now, let's look at the bank transactions stored in the`~/wareville_logs/rds.log` file.

Since the log entries are different from the logs we previously investigated, McSkidy provided some guidance on how to analyse them. According to her, we can use the following command to show all the bank transactions.

**Note:** Grep is a Unix command-line utility used for searching strings within a file or an input stream.

```shell-session
ubuntu@tryhackme:~/wareville_logs$ grep INSERT rds.log
```

From the command above, McSkidy explained that all INSERT queries from the RDS log pertain to who received the donations made by the townspeople. Given this, we can see in the output the two recipients of all donations made within November 28th, 2024.


```shell-session
---REDACTED FOR BREVITY---
2024-11-28T15:22:17.728Z 2024-11-28T15:22:17.728648Z	 263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('8839 2219 1329 6917', 'Care4wares Fund', 342.80)
2024-11-28T15:22:18.569Z 2024-11-28T15:22:18.569279Z	 263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('8839 2219 1329 6917', 'Care4wares Fund', 929.57)
2024-11-28T15:23:02.605Z 2024-11-28T15:23:02.605700Z	 263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('----- REDACTED ----', 'Mayor Malware', 193.45)
2024-11-28T15:23:02.792Z 2024-11-28T15:23:02.792161Z	 263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('----- REDACTED ----', 'Mayor Malware', 998.13)
---REDACTED FOR BREVITY---
```

As shown above, the Care4wares Fund received all the donations until it changed into a different account at a specific time. The logs also reveal who received the donations afterwards, given the account owner's name. With all these findings, McSkidy confirmed the assumptions made during the investigation of the S3 bucket since the sudden change in bank details was reflected in the database logs. The timeline of events collected by McSkidy explains the connection of actions conducted by the culprit.

| | | |
| ------------------- | ------------------------------------- | ---------------------------------------------- |
| **Timestamp** | **Source** | **Event** |
| 2024-11-28 15:22:18 | CloudWatch RDS logs (rds.log) | Last donation received by the Care4wares Fund. |
| 2024-11-28 15:22:39 | CloudTrail logs (cloudtrail_log.json) | Bank details update on S3 bucket. |
| 2024-11-28 15:23:02 | CloudWatch RDS logs (rds.log) | First donation received by Mayor Malware. |
| | | |

## Questions
----



![Pasted image 20241207132005.png](../../IMAGES/Pasted%20image%2020241207132005.png)

A lot of questions for these day, let's go one by one:

### 1
---

To check for activity by user glitch, we can use the following command:

```
jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], 
 (.Records[] | select(.sourceIPAddress=="53.94.201.69" and .userIdentity.userName == "glitch") | 
 [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | 
 @tsv' cloudtrail_log.json | column -t -s $'\t'
```

Output would be the following:

![Pasted image 20241207132322.png](../../IMAGES/Pasted%20image%2020241207132322.png)

So, answer for this question is: `PutObject`

### 2
---

The answer for this question can be found in the previous image, being the IP address: `53.94.201.69`

### 3
---

Answer for this question can also be found in that image, it is: `signin.amazonaws.com`

### 4
---

Answer can also be found in that image, it is: `2024-11-28T15:21:54Z`

### 5
---

Analyzing the logs, we can know that user created by **McSkidy** was `glitch`


### 6
---

We can use this command to check for the type of access assigned to the user:

```
jq '.Records[] | select(.eventSource=="iam.amazonaws.com" and .eventName== "AttachUserPolicy")' cloudtrail_log.json
```

![Pasted image 20241207132940.png](../../IMAGES/Pasted%20image%2020241207132940.png)

We can make the command shorter by filtering with this:

```
jq '.Records[] | select(.eventSource=="iam.amazonaws.com" and .eventName== "AttachUserPolicy") | .requestParameters.policyArn' cloudtrail_log.json
```

Answer for this question is: `AdministratorAccess`

### 7
---

Answer for this question is the same as question `2`: `53.94.201.69`


### 8
---

To check for McSkidy actual IP address we can use the following command:

```
jq -r '["Event_Time","Event_Source","Event_Name", "User_Name","User_Agent","Source_IP"],(.Records[] | select(.userIdentity.userName=="mcskidy") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A",.userAgent // "N/A",.sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```


![Pasted image 20241207133547.png](../../IMAGES/Pasted%20image%2020241207133547.png)

Real McSkidy IP address is: `31.210.15.79`

### 9
---

To check for Mayor malware's bank account number we can use the following command:

`grep INSERT rds.log`


This will output the following:

![Pasted image 20241207133805.png](../../IMAGES/Pasted%20image%2020241207133805.png)

The bank account number is: `2394 6912 7723 1294`



# End of room
---

Like that, day 7 is done!



