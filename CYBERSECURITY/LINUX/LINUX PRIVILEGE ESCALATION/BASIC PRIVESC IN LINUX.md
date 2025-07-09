# Linux Privilege Escalation Techniques

1. **SEARCHING FOR FILES WITH SUID BIT SET** 
 **Command:** `find / -perm -4000 2>/dev/null` 
 **Explanation:** Use this to search for files with the SUID bit set, which could allow a non-root user to execute the file with root privileges.

2. **SEARCHING FOR WORLD-WRITABLE FILES** 
 **Command:** `find / -type f -perm -o+w 2>/dev/null` 
 **Explanation:** Finds files that are world-writable, meaning anyone can modify them, which could be exploited for privilege escalation.

3. **SEARCHING FOR WORLD-WRITABLE DIRECTORIES** 
 **Command:** `find / -type d -perm -o+w 2>/dev/null` 
 **Explanation:** Locates directories that are world-writable, where attackers might place malicious files.

4. **SEARCHING FOR CRON JOBS** 
 **Command:** `cat /etc/crontab` 
 **Explanation:** Checks scheduled cron jobs that run scripts. If any job is executed by root and is writable by a non-privileged user, it could be a privesc vector.

5. **FINDING SUDO RIGHTS WITHOUT A PASSWORD** 
 **Command:** `sudo -l` 
 **Explanation:** Lists the commands the current user can run with `sudo`. If some commands don't require a password, they might be exploited for privilege escalation.

6. **CHECKING FOR WEAK FILE PERMISSIONS IN SUDO** 
 **Command:** `ls -la /etc/sudoers` 
 **Explanation:** Verifies if the `sudoers` file has insecure permissions that might allow modification by unauthorized users.

7. **EXPLOITING ENVIRONMENT VARIABLES WITH SUDO** 
 **Command:** `sudo -u root env` 
 **Explanation:** In some misconfigurations, environment variables could be used to gain elevated privileges when running commands via sudo.

8. **CHECKING PATH MANIPULATION VULNERABILITIES** 
 **Command:** `echo $PATH` 
 **Explanation:** Identifies potential issues with the `PATH` variable. If root executes a script using a command from an insecure path, it can be replaced by a malicious version.

9. **SEARCHING FOR PASSWORDS IN CONFIG FILES** 
 **Command:** `grep -i "password" /etc/* 2>/dev/null` 
 **Explanation:** Scans configuration files for plaintext passwords, which might allow lateral movement or privilege escalation.

10. **SEARCHING FOR PASSWORDS IN HISTORY FILES** 
 **Command:** `cat ~/.bash_history | grep password` 
 **Explanation:** Checks for sensitive information (e.g., passwords) stored in command history files.

11. **CHECKING FOR ACTIVE NFS SHARES** 
 **Command:** `cat /etc/exports` 
 **Explanation:** NFS misconfigurations can allow users to mount directories with root privileges, opening the door to privesc.

12. **SEARCHING FOR READABLE SSH KEYS** 
 **Command:** `find / -name id_rsa 2>/dev/null` 
 **Explanation:** Searches for SSH private keys that are improperly accessible, which could be used for escalation or lateral movement.

13. **USING GTFOBins FOR SUDO EXPLOITATION** 
 **Command:** `sudo <vulnerable_binary>` 
 **Explanation:** Check `GTFOBins` for binaries allowed by sudo without a password. If exploitable, they can be used to escalate privileges.

14. **SEARCHING FOR MISCONFIGURED NFS PERMISSIONS** 
 **Command:** `showmount -e` 
 **Explanation:** Reveals the export list for NFS shares. If improperly configured, it might allow access to sensitive directories.

15. **SEARCHING FOR KERNEL EXPLOITS** 
 **Command:** `uname -r` 
 **Explanation:** Displays the kernel version. Outdated kernels may have known exploits that can be used for privilege escalation.

16. **SEARCHING FOR SUDOERS MISCONFIGURATIONS** 
 **Command:** `visudo -c` 
 **Explanation:** Checks the sudoers file for syntax errors. Incorrect configurations could allow unintended privilege escalation.

17. **IDENTIFYING FILES WITH CAPABILITIES SET** 
 **Command:** `getcap -r / 2>/dev/null` 
 **Explanation:** Lists files with Linux capabilities set. Capabilities might allow bypassing privilege checks.

18. **FINDING WORLD-WRITABLE SCRIPTS** 
 **Command:** `find / -type f -name "*.sh" -perm -o=w 2>/dev/null` 
 **Explanation:** Locates writable shell scripts, which could be modified to inject malicious code that executes with elevated privileges.

19. **SEARCHING FOR WRITEABLE CRON SCRIPTS** 
 **Command:** `find /etc/cron* -type f -perm -o+w 2>/dev/null` 
 **Explanation:** Identifies writable cron jobs, allowing attackers to inject code to be executed as root.

20. **SEARCHING FOR POTENTIAL SUID ROOT SHELLS** 
 **Command:** `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` 
 **Explanation:** Finds files owned by root with the SUID bit set. These can sometimes be exploited for privilege escalation.

21. **ENUMERATING RUNNING SERVICES** 
 **Command:** `ps aux | grep root` 
 **Explanation:** Lists running services under root. Misconfigured services might allow attackers to escalate privileges.

22. **SEARCHING FOR WRITABLE SERVICE FILES** 
 **Command:** `find /lib/systemd/system/ -perm -o+w` 
 **Explanation:** Finds writable service files, which could be modified to execute malicious code with root privileges.

23. **ENUMERATING NFS ROOT SQUASH SETTINGS** 
 **Command:** `grep no_root_squash /etc/exports` 
 **Explanation:** Checks NFS exports for root squash misconfigurations. If disabled, root privileges on the client are mapped to root privileges on the server.

24. **CHECKING FOR WEAK FILE PERMISSIONS ON PASSWORD FILES** 
 **Command:** `ls -l /etc/passwd /etc/shadow` 
 **Explanation:** Verifies if password files (`/etc/passwd` and `/etc/shadow`) have weak permissions, allowing unauthorized access.

25. **CHECKING FOR OPEN LISTENING SERVICES** 
 **Command:** `netstat -tuln` 
 **Explanation:** Lists open listening ports and services. Unsecured services running as root might be exploitable.

26. **EXPLOITING ABUSED SUDO ACCESS TO `LD_PRELOAD`** 
 **Command:** `sudo LD_PRELOAD=/path/to/malicious.so <command>` 
 **Explanation:** If `LD_PRELOAD` is allowed for a binary, it can be used to load a malicious library and escalate privileges.

27. **ABUSING SUDO ACCESS TO EDITORS (LIKE NANO OR VI)** 
 **Command:** `sudo nano /etc/sudoers` 
 **Explanation:** If a text editor can be run with sudo, you can use it to open and modify privileged files.

28. **CHECKING FOR USEFUL SUDO ENVIRONMENT VARIABLES** 
 **Command:** `sudo -V | grep "env_keep"` 
 **Explanation:** Lists environment variables that are preserved when using `sudo`, potentially exploitable for privilege escalation.

29. **SEARCHING FOR WRITABLE SYSTEM BINARIES** 
 **Command:** `find /usr/bin -perm -o+w 2>/dev/null` 
 **Explanation:** Identifies writable binaries in system directories. Modifying these could lead to privilege escalation.

30. **ABUSING SUDO ACCESS TO SYSTEMCTL** 
 **Command:** `sudo systemctl` 
 **Explanation:** If systemctl is allowed without a password, services can be modified to escalate privileges by executing malicious commands.

