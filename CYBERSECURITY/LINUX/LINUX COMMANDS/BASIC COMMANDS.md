# Linux Commands Explained

1. `ls` 
 Explanation: Lists directory contents. 
 Example: `ls -l` (List files in long format)

2. `cd` 
 Explanation: Changes the current directory. 
 Example: `cd /home` (Moves to the /home directory)

3. `pwd` 
 Explanation: Prints the current working directory. 
 Example: `pwd`

4. `mkdir` 
 Explanation: Creates a new directory. 
 Example: `mkdir myFolder`

5. `rmdir` 
 Explanation: Removes empty directories. 
 Example: `rmdir myFolder`

6. `rm` 
 Explanation: Removes files or directories. 
 Example: `rm file.txt` (Removes file.txt)

7. `touch` 
 Explanation: Creates an empty file or updates the timestamp of a file. 
 Example: `touch newfile.txt`

8. `cp` 
 Explanation: Copies files or directories. 
 Example: `cp file1.txt file2.txt` (Copies file1 to file2)

9. `mv` 
 Explanation: Moves or renames files and directories. 
 Example: `mv file1.txt /home/user/` (Moves file1.txt to /home/user/)

10. `cat` 
 Explanation: Concatenates and displays file content. 
 Example: `cat file.txt`

11. `nano` 
 Explanation: Opens a basic text editor. 
 Example: `nano file.txt`

12. `vi` 
 Explanation: Opens the vi text editor. 
 Example: `vi file.txt`

13. `sudo` 
 Explanation: Executes commands as the superuser (admin). 
 Example: `sudo apt-get update`

14. `chmod` 
 Explanation: Changes file permissions. 
 Example: `chmod 755 script.sh`

15. `chown` 
 Explanation: Changes file owner and group. 
 Example: `chown user:group file.txt`

16. `df` 
 Explanation: Displays disk space usage. 
 Example: `df -h` (Shows human-readable format)

17. `du` 
 Explanation: Displays file and directory space usage. 
 Example: `du -sh folder/` (Summarizes the total size of a folder)

18. `ps` 
 Explanation: Displays information about running processes. 
 Example: `ps aux`

19. `kill` 
 Explanation: Kills a process by its PID. 
 Example: `kill 1234` (Kills process with PID 1234)

20. `killall` 
 Explanation: Kills all instances of a process by name. 
 Example: `killall firefox`

21. `top` 
 Explanation: Displays real-time system processes and resource usage. 
 Example: `top`

22. `htop` 
 Explanation: Interactive process viewer (better version of `top`). 
 Example: `htop`

23. `free` 
 Explanation: Displays memory usage. 
 Example: `free -h` (Human-readable format)

24. `uptime` 
 Explanation: Shows how long the system has been running. 
 Example: `uptime`

25. `uname` 
 Explanation: Displays system information. 
 Example: `uname -a`

26. `whoami` 
 Explanation: Prints the current user. 
 Example: `whoami`

27. `man` 
 Explanation: Displays the manual for a command. 
 Example: `man ls`

28. `grep` 
 Explanation: Searches for patterns in text. 
 Example: `grep "hello" file.txt`

29. `find` 
 Explanation: Searches for files in a directory hierarchy. 
 Example: `find /home -name file.txt`

30. `locate` 
 Explanation: Quickly finds files by name. 
 Example: `locate file.txt`

31. `history` 
 Explanation: Shows command history. 
 Example: `history`

32. `alias` 
 Explanation: Creates shortcuts for commands. 
 Example: `alias ll='ls -la'`

33. `unalias` 
 Explanation: Removes an alias. 
 Example: `unalias ll`

34. `echo` 
 Explanation: Prints text or variables to the terminal. 
 Example: `echo "Hello, World!"`

35. `wget` 
 Explanation: Downloads files from the web. 
 Example: `wget https://example.com/file.zip`

36. `curl` 
 Explanation: Transfers data from or to a server. 
 Example: `curl https://example.com`

37. `tar` 
 Explanation: Archives files into tarballs. 
 Example: `tar -czvf archive.tar.gz folder/`

38. `zip` 
 Explanation: Compresses files into a zip archive. 
 Example: `zip -r archive.zip folder/`

39. `unzip` 
 Explanation: Extracts zip files. 
 Example: `unzip archive.zip`

40. `scp` 
 Explanation: Securely copies files between systems. 
 Example: `scp file.txt user@remote:/path`

41. `ssh` 
 Explanation: Securely logs into a remote machine. 
 Example: `ssh user@hostname`

42. `ping` 
 Explanation: Tests network connectivity to a host. 
 Example: `ping google.com`

43. `traceroute` 
 Explanation: Displays the path packets take to a network host. 
 Example: `traceroute google.com`

44. `nslookup` 
 Explanation: Queries DNS information. 
 Example: `nslookup google.com`

45. `dig` 
 Explanation: DNS lookup utility. 
 Example: `dig google.com`

46. `ifconfig` 
 Explanation: Displays network interface information (deprecated, use `ip` instead). 
 Example: `ifconfig`

47. `ip` 
 Explanation: Displays and manages network interfaces. 
 Example: `ip addr show`

48. `netstat` 
 Explanation: Shows network connections, routing tables, and interface statistics. 
 Example: `netstat -tuln`

49. `ss` 
 Explanation: Utility to investigate sockets. 
 Example: `ss -tuln`

50. `iptables` 
 Explanation: Configures network packet filtering rules. 
 Example: `iptables -L`

51. `firewalld` 
 Explanation: Manages firewall rules dynamically. 
 Example: `firewall-cmd --state`

52. `systemctl` 
 Explanation: Controls the systemd system and service manager. 
 Example: `systemctl restart apache2`

53. `journalctl` 
 Explanation: Views logs collected by the systemd journal. 
 Example: `journalctl -xe`

54. `dmesg` 
 Explanation: Prints kernel ring buffer messages. 
 Example: `dmesg | grep error`

55. `mount` 
 Explanation: Mounts a file system. 
 Example: `mount /dev/sda1 /mnt`

56. `umount` 
 Explanation: Unmounts a file system. 
 Example: `umount /mnt`

57. `df` 
 Explanation: Displays disk space usage. 
 Example: `df -h`

58. `fdisk` 
 Explanation: Partitioning tool for disk drives. 
 Example: `fdisk -l`

59. `mkfs` 
 Explanation: Formats a disk with a filesystem. 
 Example: `mkfs.ext4 /dev/sda1`

60. `fsck` 
 Explanation: Checks the integrity of a file system. 
 Example: `fsck /dev/sda1`

61. `ln` 
 Explanation: Creates hard and symbolic links. 
 Example: `ln -s /path/to/file linkname`

62. `blkid` 
 Explanation: Identifies block devices by UUID. 
 Example: `blkid`

63. `parted` 
 Explanation: Disk partitioning tool. 
 Example: `parted /dev/sda`

64. `du` 
 Explanation: Estimates file space usage. 
 Example: `du -h folder/`

65. `lsblk` 
 Explanation: Lists information about block devices. 
 Example: `lsblk`

66. `lsusb` 
 Explanation: Lists USB devices. 
 Example: `lsusb`

67. `lspci` 
 Explanation: Lists PCI devices. 
 Example: `lspci`

68. `hostnamectl` 
 Explanation: Set or view the system hostname. 
 Example: `hostnamectl`

69. `timedatectl` 
 Explanation: Set or view the date and time settings.
