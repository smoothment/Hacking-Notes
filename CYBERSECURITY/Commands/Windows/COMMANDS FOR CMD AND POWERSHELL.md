These are basic commands, so, no need to go any further:

```
1. ipconfig - Get-NetIPAddress 
2. ipconfig /all - Get-NetIPConfiguration (only shows DNS-Server and Gateway) 
3. findstr - Select-String 
4. ipconfig /release - Invoke-WmiMethod -Class Win32_NetworkAdapterConfiguration -Name ReleaseDHCPLeaseAll 
5. ipconig /renew - Invoke-WmiMethod -Class Win32_NetworkAdapterConfiguration -Name RenewDHCPLeaseAll 
6. ipconfig /displaydns - Get-DnsClientCache (you may use '| Format-List' to get all colums) 
7. clip - Set-Clipboard 
8. ipconfig /flushdns - Clear-DnsClientCache 
9. nslookup - Resolve-DnsName 
10. cls - Clear-Host (or just Ctrl+L) 
11. getmac /v - Get-NetAdapter 
12. powercfg - no equivalent afaik 
13. assoc - no equivalent afaik (also assoc does not seem to exist on my Windows 11 21H2 VM) 
14. chkdsk - Repair-Volume 
15. sfc - no equivalent afaik 
16. DISM - no equivalent afaik 
17. tasklist - Get-Process 
18. taskkill - Stop-Process 
19. netsh - no equivalent afaik but you can manipulate the Windows firewall, just search with Get-Command firewall 
20. ping - Test-NetConnection 
21. ping /t - Test-Connection -Count 100000 (Test-Connection gives you much more data, while Test-NetConnection just shows the IP and Latency to the target) 
22. tracert - Test-NetConnection -TraceRoute 
23. netstat - Get-NetTCPConnection 
24. route print - Get-NetRoute 
25. route add - New-NetRoute 
26. route delete - Remove-NetRoute 
27. shutdown - Stop-Computer 
28. restart - Restart-Computer
29. Expand-Archive - Extract file from a zip Archive 
30. Compress-Archive - Create a zip Archive
```
