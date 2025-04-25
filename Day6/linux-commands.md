## Linux Command Cheatsheet

This cheatsheet covers some fundamental Linux commands, categorized for easier reference. Many commands require root privileges, often obtained using `sudo`. Use `man <command>`, `info <command>`, or `<command> --help` for more details.

### Getting Help / Documentation

| Command             | Description                                                                 | Examples / Notes                       |
| :------------------ | :-------------------------------------------------------------------------- | :------------------------------------- |
| `man <command>`     | Display the manual page for a command.                                      | Press `q` to quit. Use `/` to search.  |
| `info <command>`    | Display the GNU Info documentation (often more detailed than `man`).        | Press `q` to quit.                     |
| `<command> --help`  | Display a brief usage summary and options for a command.                    |                                        |
| `man hier`          | Display description of the filesystem hierarchy.                            |                                        |
| `mandb`             | Create or update the manual page index caches.                              | Usually run with `sudo`.               |
| *Documentation Files* | General location for additional documentation packages.                     | Often found in `/usr/share/doc`.       |

### File and Directory Management

| Command                 | Description                                                     | Examples / Notes                                    |
| :---------------------- | :-------------------------------------------------------------- | :-------------------------------------------------- |
| `ls`                    | List directory contents.                                        | `-l`: long format, `-a`: show hidden files.         |
| `cd <directory>`        | Change the current directory.                                   | `cd ..` (up), `cd ~` or `cd` (home), `cd -` (previous) |
| `pwd`                   | Print the working directory (show the current directory path).  |                                                     |
| `mkdir <directory_name>`| Create a new directory.                                         |                                                     |
| `rmdir <directory_name>`| Remove an *empty* directory.                                    |                                                     |
| `cp <source> <dest>`    | Copy files or directories.                                      | `-r`: recursive copy for directories.               |
| `mv <source> <dest>`    | Move or rename files or directories.                            | `mv old new` (rename), `mv file dir/` (move)        |
| `rm <file_name>`        | Remove (delete) a file.                                         | `-r`: recursive (dirs), `-f`: force. Use with caution! |
| `touch <file_name>`     | Create an empty file or update the timestamp of an existing file. |                                                     |

### Text File Viewing and Manipulation

| Command                 | Description                                                              | Examples / Notes                                                                 |
| :---------------------- | :----------------------------------------------------------------------- | :------------------------------------------------------------------------------- |
| `cat <file_name>`       | Concatenate and display file content.                                    | `cat f1 f2 > new`, `cat file \| wc -l` (pipe to count lines)                     |
| `less <file_name>`      | View file content page by page (allows scrolling).                       | Press `q` to quit.                                                               |
| `more <file_name>`      | View file content page by page (older, less flexible).                   | Press spacebar for next page, `q` to quit.                                       |
| `head <file_name>`      | Display the first few lines of a file (default 10).                      | `-n 20`: display first 20 lines.                                                 |
| `tail <file_name>`      | Display the last few lines of a file (default 10).                       | `-n 20`: display last 20 lines.<br>`-f`: follow file updates (Ctrl+C to stop). |
| `grep <pattern> <file>` | Search for a pattern within a file.                                      | `-i`: case-insensitive, `-r`: recursive search in directory.                     |
| `wc`                    | Word count (lines, words, characters).                                   | `-l`: lines, `-w`: words, `-c`: bytes.                                           |
| `echo <text>`           | Display a line of text or variable value.                                | `echo "Hi"`, `echo $HOME`, `echo $USER`, `echo $SHELL`                           |

### System Information

| Command             | Description                                                              | Examples / Notes                                    |
| :------------------ | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `uname`             | Print system information.                                                | `-a`: all info, `-r`: kernel release.               |
| `hostname`          | Show the system's hostname.                                              |                                                     |
| `uptime`            | Show how long system has run, logged-in users, load averages.            |                                                     |
| `free`              | Display memory usage (RAM and swap).                                     | `-h`: human-readable format.                        |
| `cat /proc/meminfo` | Show detailed memory information.                                        |                                                     |
| `lscpu`             | Display information about the CPU architecture.                          |                                                     |
| `cat /proc/cpuinfo` | Show detailed CPU information.                                           |                                                     |
| `cat /proc/version` | Display kernel version, GCC version, etc.                                |                                                     |
| `top` / `htop`      | Display running processes and system resource usage interactively.       | `htop` often preferred (may need install). `q` to quit. |

### Disk Management

| Command               | Description                                                              | Examples / Notes             |
| :-------------------- | :----------------------------------------------------------------------- | :--------------------------- |
| `df`                  | Display disk space usage for mounted filesystems.                        | `-h`: human-readable format. |
| `du`                  | Display disk usage of files/directories.                                 | `-sh <dir>`: total size.<br>`-h`: sizes of subdirs. |
| `fdisk -l`            | List disk partition tables.                                              | Requires root/sudo.          |
| `lsblk`               | List block devices (disks and partitions).                               |                              |
| `cat /proc/diskstats` | Show disk I/O statistics.                                                |                              |

### Process Management

| Command             | Description                                                              | Examples / Notes                                    |
| :------------------ | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `ps`                | List running processes.                                                  | `aux`: BSD syntax (all users), `-ef`: SysV syntax.  |
| `top` / `htop`      | Interactive process viewer.                                              | See System Information section.                     |
| `kill <PID>`        | Send a signal to terminate a process (by Process ID).                    | Default: TERM (15). `-9`: SIGKILL (force kill).     |
| `pkill <name>`      | Kill processes by name.                                                  |                                                     |
| `pgrep <name>`      | Find the Process ID (PID) of processes by name.                          |                                                     |

### Networking

| Command                     | Description                                                              | Examples / Notes                                    |
| :-------------------------- | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `ip addr` or `ip a`         | Show network interface configuration (preferred).                        |                                                     |
| `ifconfig`                  | Show network interface configuration (older command).                    | May not be installed by default on newer systems.   |
| `ping <host_or_ip>`         | Send ICMP ECHO_REQUEST packets to test connectivity.                     | Press `Ctrl+C` to stop.                             |
| `ss`                        | Display network connections, listening ports, etc. (preferred).          | `-tulnp`: common options (TCP, UDP, listening, numeric, process) |
| `netstat`                   | Display network connections, listening ports, etc. (older command).      | `-tulnp`: common options.                           |
| `traceroute <host_or_ip>`   | Trace the network path (hops) to a destination host.                     |                                                     |
| `wget <URL>`                | Download files from the web (non-interactive).                           |                                                     |
| `curl <URL>`                | Transfer data from or to a server (versatile).                           | `-O`: download file with original name.             |
| `ssh <user>@<host_or_ip>`   | Connect to a remote host securely using SSH.                             |                                                     |
| `scp <src> <user>@<host>:<dest>` | Securely copy files between hosts using SSH.                           |                                                     |
| `nmap <options> <target>`   | Network exploration tool and security / port scanner.                    | Requires installation, powerful tool.               |

### Permissions and Ownership

| Command                          | Description                                                              | Examples / Notes                                                                                                                            |
| :------------------------------- | :----------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `chmod <perms> <file/dir>`       | Change file/directory permissions.                                       | *Symbolic:* `u+x` (user add execute).<br>*Octal:* `755` (rwxr-xr-x).<br>(Read=4, Write=2, Execute=1). `u/g/o/a` = user/group/other/all. |
| `chown <user>:<group> <file/dir>`| Change file/directory owner and group.                                   | `-R`: recursive change. `chown www:www file`.                                                                                               |
| `chgrp <group> <file/dir>`       | Change file/directory group ownership.                                   |                                                                                                                                             |
| *Permission Notations (`ls -l`)* | Understanding the output of `ls -l`.                                     | 1st char: `-`/`d`/`l`/`c`/`b`.<br>Next 9 (3 sets): `rwx` for User, Group, Others.                                                          |

### User Management & Environment

| Command             | Description                                                              | Examples / Notes             |
| :------------------ | :----------------------------------------------------------------------- | :--------------------------- |
| `whoami`            | Print the effective username of the current user.                        |                              |
| `id`                | Print real and effective user and group IDs.                             |                              |
| `w`                 | Show who is logged on and what they are doing.                           |                              |
| `sudo <command>`    | Execute a command as the superuser (root) or another user.               |                              |
| `sudo su` / `sudo -i` | Switch to an interactive root shell.                                     |                              |
| `exit`              | Exit the current shell or logout.                                        |                              |
| `echo $USER`        | Display the current username.                                            |                              |
| `echo $HOME`        | Display the path to the current user's home directory.                   |                              |
| `echo $SHELL`       | Display the path to the current user's default shell.                    |                              |
| `cat /etc/shells`   | List available login shells on the system.                               |                              |

### Shell / Command History

| Command             | Description                                                              | Examples / Notes                                    |
| :------------------ | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `history`           | Display the command history list with numbers.                           |                                                     |
| `!!`                | Execute the last command again.                                          |                                                     |
| `!<number>`         | Execute the command with that number from `history`.                     | e.g., `!101`                                        |
| `!<string>`         | Execute the most recent command starting with `<string>`.                | e.g., `!ls`                                         |
| `Ctrl+R`            | Reverse-i-search (start typing to search history).                       |                                                     |
| `echo $HISTSIZE`    | Display the number of history lines stored in memory.                    |                                                     |
| `echo $HISTFILESIZE`| Display the maximum number of lines stored in the history file.          | File often `~/.bash_history`, `~/.zsh_history`, etc. |

### Date & Time

| Command             | Description                                                              | Examples / Notes                                    |
| :------------------ | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `date`              | Print or set the system date and time.                                   |                                                     |
| `timedatectl`       | Query and change the system clock and its settings.                      | `status`, `list-timezones`, `set-timezone <TZ>`     |
| `cal` / `ncal`      | Display a calendar.                                                      |                                                     |
| `hwclock`           | Query and set the hardware clock (RTC).                                  |                                                     |

### Searching Files

| Command                       | Description                                                              | Examples / Notes                                    |
| :---------------------------- | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `find <path> <criteria>`      | Search for files/directories based on various criteria.                  | `-name "*.txt"`, `-type f`, `-size +100M`, `-mmin -60` |
| `locate <filename_pattern>`   | Find files quickly using a pre-built database.                           | Run `sudo updatedb` to update database.             |
| `grep`                        | Search *within* files for patterns.                                      | See Text File Viewing section.                      |

### Package Management (Distribution Dependent)

**Debian/Ubuntu (apt):**

| Command                 | Description                                                              | Examples / Notes                                    |
| :---------------------- | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `sudo apt update`       | Refresh package list from repositories.                                  | Use `-y` to auto-confirm.                           |
| `sudo apt upgrade`      | Upgrade installed packages to newest versions.                           | Use `-y` to auto-confirm.                           |
| `sudo apt full-upgrade` | Upgrade packages, potentially removing/installing others.                |                                                     |
| `sudo apt install <pkg>`| Install a package.                                                       | Use `-y` to auto-confirm. `apt search <keyword>`    |
| `sudo apt remove <pkg>` | Remove a package (keeps configuration files).                            |                                                     |
| `sudo apt purge <pkg>`  | Remove a package and its configuration files.                            |                                                     |
| `apt show <pkg>`        | Show details about a package.                                            |                                                     |
| `apt list --upgradable` | List packages that have available upgrades.                              |                                                     |
| `dpkg -l <pattern>`     | List installed packages matching pattern (lower-level).                  | `dpkg -l kali-linux-firmware`                       |
| `cat /etc/apt/sources.list` | View main repository configuration file.                               | Also check `/etc/apt/sources.list.d/`.              |

**Fedora (dnf):**

| Command                 | Description                                                              | Examples / Notes             |
| :---------------------- | :----------------------------------------------------------------------- | :--------------------------- |
| `sudo dnf check-update` | Check for updates.                                                       |                              |
| `sudo dnf upgrade`      | Upgrade installed packages.                                              | Use `-y` to auto-confirm.    |
| `sudo dnf install <pkg>`| Install a package.                                                       | Use `-y` to auto-confirm.    |
| `sudo dnf remove <pkg>` | Remove a package.                                                        |                              |
| `dnf search <keyword>`  | Search for available packages.                                           |                              |
| `dnf info <pkg>`        | Show details about a package.                                            |                              |

**CentOS/RHEL (yum/dnf):**

| Command                 | Description                                                              | Examples / Notes                                    |
| :---------------------- | :----------------------------------------------------------------------- | :-------------------------------------------------- |
| `sudo yum/dnf check-update` | Check for updates.                                                   | Older versions use `yum`, newer use `dnf`.          |
| `sudo yum/dnf update/upgrade` | Upgrade installed packages.                                          | Use `-y` to auto-confirm. `dnf` uses `upgrade`.     |
| `sudo yum/dnf install <pkg>`| Install a package.                                                   | Use `-y` to auto-confirm.                           |
| `sudo yum/dnf remove <pkg>` | Remove a package.                                                    |                                                     |
| `yum/dnf search <keyword>`| Search for available packages.                                           |                                                     |
| `yum/dnf info <pkg>`    | Show details about a package.                                            |                                                     |

### Archiving and Compression

| Command                               | Description                                                              | Examples / Notes             |
| :------------------------------------ | :----------------------------------------------------------------------- | :--------------------------- |
| `tar -cvf <archive.tar> <files>`      | Create a `.tar` archive.                                                 | `c`=create, `v`=verbose, `f`=file |
| `tar -xvf <archive.tar>`              | Extract files from a `.tar` archive.                                     | `x`=extract                  |
| `tar -czvf <archive.tar.gz> <files>`  | Create a gzip compressed `.tar` archive.                                 | `z`=gzip                     |
| `tar -xzvf <archive.tar.gz>`          | Extract files from a gzip compressed `.tar` archive.                     |                              |
| `tar -cjvf <archive.tar.bz2> <files>` | Create a bzip2 compressed `.tar` archive.                                | `j`=bzip2                    |
| `tar -xjvf <archive.tar.bz2>`         | Extract files from a bzip2 compressed `.tar` archive.                    |                              |
| `gzip <file_name>`                    | Compress a file (replaces original with `<file_name>.gz`).               |                              |
| `gunzip <file_name.gz>`               | Decompress a `.gz` file.                                                 |                              |
| `zip <archive.zip> -r <files>`        | Create a `.zip` archive recursively.                                     |                              |
| `unzip <archive.zip>`                 | Extract files from a `.zip` archive.                                     |                              |

### Important System Files (View with `cat`)

These files, primarily within the `/proc` pseudo-filesystem and `/etc` directory, contain valuable system configuration and status information. Accessing some files may require root privileges (`sudo`).

| File Path                       | Description                                                                              | Notes                                                      |
| :------------------------------ | :--------------------------------------------------------------------------------------- | :--------------------------------------------------------- |
| `/proc/version`                 | Displays the Linux kernel version, GCC version used to build it, and other build info.   |                                                            |
| `/proc/cmdline`                 | Shows the parameters passed to the kernel at boot time.                                  |                                                            |
| `/proc/cpuinfo`                 | Contains detailed information about the system's CPU(s).                                 |                                                            |
| `/proc/meminfo`                 | Provides detailed information about RAM and swap memory usage.                           |                                                            |
| `/proc/diskstats`               | Displays I/O statistics for block devices (disks).                                       |                                                            |
| `/proc/partitions`              | Lists the partitions known to the kernel.                                                |                                                            |
| `/proc/filesystems`             | Shows the filesystems supported by the kernel.                                           |                                                            |
| `/proc/mounts` or `/etc/mtab`   | Lists currently mounted filesystems.                                                     | `/proc/mounts` is generally more up-to-date.               |
| `/proc/net/dev`                 | Displays network interface statistics (bytes/packets received/transmitted, errors, etc.). |                                                            |
| `/proc/uptime`                  | Contains system uptime (seconds) and time spent idle (seconds).                          |                                                            |
| `/proc/loadavg`                 | Shows system load averages (1, 5, 15 min), running/total processes, last PID.            |                                                            |
| `/etc/os-release`               | Contains operating system identification data (distribution name, version, etc.).        |                                                            |
| `/etc/hostname`                 | Contains the system's hostname.                                                          |                                                            |
| `/etc/hosts`                    | Local DNS lookup file mapping IP addresses to hostnames.                                 |                                                            |
| `/etc/resolv.conf`              | Specifies the DNS name servers used by the system for domain name resolution.            |                                                            |
| `/etc/fstab`                    | Static information about filesystems, including mount points and options used at boot.   |                                                            |
| `/etc/passwd`                   | User account information (username, UID, GID, home dir, shell).                          | Passwords *not* stored here on modern systems.             |
| `/etc/shadow`                   | Secure user account information, including hashed passwords.                             | Requires root privileges to read.                          |
| `/etc/group`                    | Group account information.                                                               |                                                            |
| `/etc/shells`                   | Lists the paths of valid login shells available on the system.                           |                                                            |
| `/etc/apt/sources.list`         | Main list of package repositories used by APT (Debian/Ubuntu).                           | Also check files in `/etc/apt/sources.list.d/`.            |
| `/etc/yum.repos.d/`             | Directory containing repository configuration files for YUM/DNF (CentOS/RHEL/Fedora).    |                                                            |
| `/var/log/syslog` or `/var/log/messages` | Main system log file.                                                            | Location varies by distribution/config. Requires `sudo`. |
| `/var/log/auth.log` or `/var/log/secure` | Authentication and authorization logs (logins, sudo usage, etc.).                | Requires `sudo`.                                           |
| `/var/log/dmesg`                | Kernel ring buffer messages (boot, hardware, drivers).                                   | Can also be viewed with the `dmesg` command. Requires `sudo`. |

---
**Note:** The `/proc` filesystem is virtual and reflects the current state of the kernel; files here don't exist on disk in the traditional sense.
