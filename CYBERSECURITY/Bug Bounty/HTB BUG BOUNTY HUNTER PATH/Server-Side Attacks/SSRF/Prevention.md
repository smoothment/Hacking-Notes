---
sticker: lucide//server
---
After discussing identifying and exploiting SSRF vulnerabilities, we will dive into SSRF prevention and mitigation techniques.

---

## Prevention

Mitigations and countermeasures against SSRF vulnerabilities can be implemented at the web application or network layers. If the web application fetches data from a remote host based on user input, proper security measures to prevent SSRF scenarios are crucial.Â 

The remote origin data is fetched from should be checked against a whitelist to prevent an attacker from coercing the server to make requests against arbitrary origins.Â A whitelistÂ prevents an attacker from making unintended requests to internal systems.Â Additionally, the URL scheme and protocol used in the request need to be restricted to prevent attackers from supplying arbitrary protocols.Â Instead, it should be hardcoded or checked against a whitelist. As with any user input, input sanitization can help prevent unexpected behavior that may lead to SSRF vulnerabilities.Â 

On the network layer, appropriate firewall rules can prevent outgoing requests to unexpected remote systems. If properly implemented, a restricting firewall configuration can mitigate SSRF vulnerabilities in the web application by dropping any outgoing requests to potentially interesting target systems. Additionally, network segmentation can prevent attackers from exploiting SSRF vulnerabilities to access internal systems.

For more details on the SSRF mitigation measures, check out theÂ [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

