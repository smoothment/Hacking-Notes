An essential feature of web proxy tools is their web scanners. Burp Suite comes withÂ `Burp Scanner`, a powerful scanner for various types of web vulnerabilities, using aÂ `Crawler`Â for building the website structure, andÂ `Scanner`Â for passive and active scanning.

Burp Scanner is a Pro-Only feature, and it is not available in the free Community version of Burp Suite. However, given the wide scope that Burp Scanner covers and the advanced features it includes, it makes it an enterprise-level tool, and as such, it is expected to be a paid feature.

---

## Target Scope

To start a scan in Burp Suite, we have the following options:

1. Start scan on a specific request from Proxy History
2. Start a new scan on a set of targets
3. Start a scan on items in-scope

To start a scan on a specific request from Proxy History, we can right-click on it once we locate it in the history, and then selectÂ `Scan`Â to be able to configure the scan before we run it, or selectÂ `Passive/Active Scan`Â to quickly start a scan with the default configurations:

![Scan Request](https://academy.hackthebox.com/storage/modules/110/burp_scan_request.jpg)

We may also click on theÂ `New Scan`Â button on theÂ `Dashboard`Â tab, which would open theÂ `New Scan`Â configuration window to configure a scan on a set of custom targets. Instead of creating a custom scan from scratch, let's see how we can utilize the scope to properly define what's included/excluded from our scans using theÂ `Target Scope`. TheÂ `Target Scope`Â can be utilized with all Burp features to define a custom set of targets that will be processed. Burp also allows us to limit Burp to in-scope items to save resources by ignoring any out-of-scope URLs.

Note: We will be scanning the web application from the exercise found at the end of the next section. If you obtain a license to use Burp Pro, you may spawn the target at the end of the next section and follow along here.

If we go to (`Target>Site map`), it will show a listing of all directories and files burp has detected in various requests that went through its proxy:

![Site Map](https://academy.hackthebox.com/storage/modules/110/burp_site_map_before.jpg)

To add an item to our scope, we can right-click on it and selectÂ `Add to scope`:

![Add to Scope](https://academy.hackthebox.com/storage/modules/110/burp_add_to_scope.jpg)

Note: When you add the first item to your scope, Burp will give you the option to restrict its features to in-scope items only, and ignore any out-of-scope items.

We may also need to exclude a few items from scope if scanning them may be dangerous or may end our session 'like a logout function'. To exclude an item from our scope, we can right-click on any in-scope item and selectÂ `Remove from scope`. Finally, we can go to (`Target>Scope`) to view the details of our scope. Here, we may also add/remove other items and use advanced scope control to specify regex patterns to be included/excluded.

![Target Scope](https://academy.hackthebox.com/storage/modules/110/burp_target_scope.jpg)

---

## Crawler

Once we have our scope ready, we can go to theÂ `Dashboard`Â tab and click onÂ `New Scan`Â to configure our scan, which would be automatically populated with our in-scope items:

![New Scan](https://academy.hackthebox.com/storage/modules/110/burp_new_scan.jpg)

We see that Burp gives us two scanning options:Â `Crawl and Audit`Â andÂ `Crawl`. A Web Crawler navigates a website by accessing any links found in its pages, accessing any forms, and examining any requests it makes to build a comprehensive map of the website. In the end, Burp Scanner presents us with a map of the target, showing all publicly accessible data in a single place. If we selectÂ `Crawl and Audit`, Burp will run its scanner after its Crawler (as we will see later).

Note: A Crawl scan only follows and maps links found in the page we specified, and any pages found on it. It does not perform a fuzzing scan to identify pages that are never referenced, like what dirbuster or ffuf would do. This can be done with Burp Intruder or Content Discovery, and then added to scope, if needed.

Let us selectÂ `Crawl`Â as a start and go to theÂ `Scan configuration`Â tab to configure our scan. From here, we may choose to click onÂ `New`Â to build a custom configuration, which would allow us to set the configurations like the crawling speed or limit, whether Burp will attempt to log in to any login forms, and a few other configurations. For the sake of simplicity, we will click on theÂ `Select from library`Â button, which gives us a few preset configurations we can pick from (or custom configurations we previously defined):

![Crawl Config](https://academy.hackthebox.com/storage/modules/110/burp_crawl_config.jpg)

We will select theÂ `Crawl strategy - fastest`Â option and continue to theÂ `Application login`Â tab. In this tab, we can add a set of credentials for Burp to attempt in any Login forms/fields it can find. We may also record a set of steps by performing a manual login in the pre-configured browser, such that Burp knows what steps to follow to gain a login session. This can be essential if we were running our scan using an authenticated user, which would allow us to cover parts of the web application that Burp may otherwise not have access to. As we do not have any credentials, we'll leave it empty.

With that, we can click on theÂ `Ok`Â button to start our Crawl scan. Once our scan starts, we can see its progress in theÂ `Dashboard`Â tab underÂ `Tasks`:

![Crawl Config](https://academy.hackthebox.com/storage/modules/110/burp_crawl_progress.jpg)

We may also click on theÂ `View details`Â button on the tasks to see more details about the running scan or click on the gear icon to customize our scan configurations further. Finally, once our scan is complete, we'll seeÂ `Crawl Finished`Â in the task info, and then we can go back to (`Target>Site map`) to view the updated site map:

![Site Map](https://academy.hackthebox.com/storage/modules/110/burp_site_map_after.jpg)

---

## Passive Scanner

Now that the site map is fully built, we may select to scan this target for potential vulnerabilities. When we choose theÂ `Crawl and Audit`Â option in theÂ `New Scan`Â dialog, Burp will perform two types of scans: AÂ `Passive Vulnerability Scan`Â and anÂ `Active Vulnerability Scan`.

Unlike an Active Scan, a Passive Scan does not send any new requests but analyzes the source of pages already visited in the target/scope and then tries to identifyÂ `potential`Â vulnerabilities. This is very useful for a quick analysis of a specific target, like missing HTML tags or potential DOM-based XSS vulnerabilities. However, without sending any requests to test and verify these vulnerabilities, a Passive Scan can only suggest a list of potential vulnerabilities. Still, Burp Passive Scanner does provide a level ofÂ `Confidence`Â for each identified vulnerability, which is also helpful for prioritizing potential vulnerabilities.

Let's start by trying to perform a Passive Scan only. To do so, we can once again select the target in (`Target>Site map`) or a request in Burp Proxy History, then right-click on it and selectÂ `Do passive scan`Â orÂ `Passively scan this target`. The Passive Scan will start running, and its task can be seen in theÂ `Dashboard`Â tab as well. Once the scan finishes, we can click onÂ `View Details`Â to review identified vulnerabilities and then select theÂ `Issue activity`Â tab:

![Passive Scan](https://academy.hackthebox.com/storage/modules/110/burp_passive_scan.jpg)

Alternately, we can view all identified issues in theÂ `Issue activity`Â pane on theÂ `Dashboard`Â tab. As we can see, it shows the list of potential vulnerabilities, their severity, and their confidence. Usually, we want to look for vulnerabilities withÂ `High`Â severity andÂ `Certain`Â confidence. However, we should include all levels of severity and confidence for very sensitive web applications, with a special focus onÂ `High`Â severity andÂ `Confident/Firm`Â confidence.

---

## Active Scanner

We finally reach the most powerful part of Burp Scanner, which is its Active Vulnerability Scanner. An active scan runs a more comprehensive scan than a Passive Scan, as follows:

1. It starts by running a Crawl and a web fuzzer (like dirbuster/ffuf) to identify all possible pages
    
2. It runs a Passive Scan on all identified pages
    
3. It checks each of the identified vulnerabilities from the Passive Scan and sends requests to verify them
    
4. It performs a JavaScript analysis to identify further potential vulnerabilities
    
5. It fuzzes various identified insertion points and parameters to look for common vulnerabilities like XSS, Command Injection, SQL Injection, and other common web vulnerabilities
    

The Burp Active scanner is considered one of the best tools in that field and is frequently updated to scan for newly identified web vulnerabilities by the Burp research team.

We can start an Active Scan similarly to how we began a Passive Scan by selecting theÂ `Do active scan`Â from the right-click menu on a request in Burp Proxy History. Alternatively, we can run a scan on our scope with theÂ `New Scan`Â button in theÂ `Dashboard`Â tab, which would allow us to configure our active scan. This time, we will select theÂ `Crawl and Audit`Â option, which would perform all of the above points and everything we have discussed so far.

We may also set the Crawl configurations (as we discussed earlier) and the Audit configurations. The Audit configurations enable us to select what type of vulnerabilities we want to scan (defaults to all), where the scanner would attempt inserting its payloads, in addition to many other useful configurations. Once again, we can select a configuration preset with theÂ `Select from library`Â button. For our test, as we are interested inÂ `High`Â vulnerabilities that may allow us to gain control over the backend server, we will select theÂ `Audit checks - critical issues only`Â option. Finally, we may add login details, as we previously saw with the Crawl configurations.

Once we select our configurations, we can click on theÂ `Ok`Â button to start the scan, and the active scan task should be added in theÂ `Tasks`Â pane in theÂ `Dashboard`Â tab:

![Active Scan](https://academy.hackthebox.com/storage/modules/110/burp_active_scan.jpg)

The scan will run all of the steps mentioned above, which is why it will take significantly longer to finish than our earlier scans depending on the configurations we selected. As the scan is running, we can view the various requests it is making by clicking on theÂ `View details`Â button and selecting theÂ `Logger`Â tab, or by going to theÂ `Logger`Â tab in Burp, which shows all requests that went through or were made by Burp:

![Logger](https://academy.hackthebox.com/storage/modules/110/burp_logger.jpg)

Once the scan is done, we can look at theÂ `Issue activity`Â pane in theÂ `Dashboard`Â tab to view and filter all of the issues identified so far. From the filter above the results, let's selectÂ `High`Â andÂ `Certain`Â and see our filtered results:

![High Vulnerabilities](https://academy.hackthebox.com/storage/modules/110/burp_high_vulnerabilities.jpg)

We see that Burp identified anÂ `OS command injection`Â vulnerability, which is ranked with aÂ `High`Â severity andÂ `Firm`Â confidence. As Burp is firmly confident that this severe vulnerability exists, we can read about it by clicking on it and reading the advisory shown and view the sent request and received response, to be able to know whether the vulnerability can be exploited or how it poses a threat on the webserver:

![Vulnerably Details](https://academy.hackthebox.com/storage/modules/110/burp_vuln_details.jpg)

---

## Reporting

Finally, once all of our scans are completed, and all potential issues have been identified, we can go to (`Target>Site map`), right-click on our target, and select (`Issue>Report issues for this host`). We will get prompted to select the export type for the report and what information we would like to include in the report. Once we export the report, we can open it in any web browser to view its details:

![Scan Report](https://academy.hackthebox.com/storage/modules/110/burp_scan_report.jpg)

As we can see, Burp's report is very organized and can be customized to only include select issues by severity/confidence. It also shows proof-of-concept details of how to exploit the vulnerability and information on how to remediate it. These reports may be used as supplementary data for the detailed reports that we prepare for our clients or the web application developers when performing a web penetration test or can be stored for our future reference. We should never merely export a report from any penetration tool and submit it to a client as the final deliverable. Instead, the reports and data generated by tools can be helpful as appendix data for clients who may need the raw scan data for remediation efforts or to import into a tracking dashboard.

Â [Previous](https://academy.hackthebox.com/module/110/section/1056)
