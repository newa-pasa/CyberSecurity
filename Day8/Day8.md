## Types of Users

Both operating systems categorize users based on their privileges:

**Windows:**

1.  **Administrator:**
    *   Has full control over the system.
    *   Can install software/hardware, access all files, change system settings, and manage other user accounts.
    *   The built-in `Administrator` account is often disabled by default for security. Users are typically added to the `Administrators` group.
    *   Subject to User Account Control (UAC) prompts by default for administrative actions.
2.  **Standard User:**
    *   Can run installed applications and manage their own files/settings.
    *   Cannot install most software, change critical system settings, or modify files belonging to other users or the system.
    *   Requires administrative credentials (via UAC prompt) to perform administrative tasks.
3.  **Guest:**
    *   Highly restricted account, often disabled by default.
    *   Intended for temporary access with very limited privileges. Cannot install software or change settings.

**Linux:**

1.  **Root User (Superuser):**
    *   The most privileged account (UID 0). Has absolute control over the system.
    *   Can access/modify any file, manage any process, change any system setting, and manage all other users.
    *   Direct login as root is often discouraged or disabled for security; administrators typically use `sudo` from their regular account.
2.  **Standard User (Regular User):**
    *   Accounts created for individual users (typically UIDs 1000+).
    *   Can run applications, manage files in their home directory, and customize their environment.
    *   Cannot access files outside their permissions, modify system-wide settings, or manage other users without elevated privileges (usually via `sudo`).
3.  **System User (Service User):**
    *   Accounts created to run specific services or applications (often with UIDs below 1000 but above 0).
    *   Typically have limited privileges, often cannot log in interactively (`nologin` shell), and own specific files/processes related to their service. Examples: `www-data`, `mysql`, `sshd`.



## User management in Windows 


### Meaning of `net` in Windows Commands

The **`net`** part of Windows commands like `net user`, `net accounts`, and `net localgroup` essentially stands for **Network**.

1.  **Origin:** The `net` command suite originates from Microsoft's early networking software (e.g., LAN Manager) and was integrated into Windows NT and subsequent versions.
2.  **Function:** It acts as a command-line interface (CLI) to manage various **network-related aspects** of Windows. Even when managing local resources like users and groups, these are often fundamental to network access and permissions.
3.  **Scope:** `net` is a gateway to many sub-commands for network and system administration, including:
    *   `net user`: User accounts (network login)
    *   `net localgroup`: Local groups (network permissions)
    *   `net share`: Network shares
    *   `net view`: Network resources
    *   `net use`: Network connections (mapped drives)
    *   `net accounts`: Account policies (network security)
    *   `net start`/`stop`: Network services
    *   `net time`: Network time synchronization
    *   `net config`: Network configuration

In essence, `net` is the primary command for interacting with core networking services and related configurations via the command line.

---
### Notes: `net user` Command (Windows)

**Purpose:**
The `net user` command is a built-in Windows command-line utility used for managing **local user accounts** on a system. It allows administrators (and sometimes standard users, depending on the operation) to view, add, modify, and delete user accounts.

**Common Syntax & Uses:**

1.  **List all local user accounts:**
    ```bash
    net user
    ```
    *   Displays a list of usernames for all local accounts on the machine.
    *   Useful for initial user enumeration.

2.  **View details of a specific user:**
    ```bash
    net user <username>
    ```
    *   Shows detailed information about the specified user account, including:
        *   Full name
        *   Account active status
        *   Password last set, expires, changeable, required
        *   Last logon time
        *   Local and Global Group memberships
    *   Crucial for understanding an account's privileges and status.

3.  **Add a new user account:**
    ```bash
    net user <username> <password> /add
    ```
    *   Creates a new local user with the specified username and password.
    *   Requires administrative privileges.
    *   For better security (avoiding password in history/logs), use `*` to be prompted:
        ```bash
        net user <username> * /add
        ```

4.  **Delete a user account:**
    ```bash
    net user <username> /delete
    ```
    *   Removes the specified local user account permanently.
    *   Requires administrative privileges. Use with caution!

5.  **Change a user's password:**
    ```bash
    net user <username> <new_password>
    ```
    *   Sets a new password for the specified user. Requires administrative privileges unless changing your own password (subject to policy).
    *   Using `*` prompts for the password securely:
        ```bash
        net user <username> *
        ```

**Managing Group Membership (`net localgroup`)**

While `net user` manages the accounts themselves, `net localgroup` is used to manage local group memberships:

1.  **Add a user to a local group:**
    ```bash
    net localgroup <groupname> <username> /add
    ```
    *   Adds the specified existing user account to the specified local group (e.g., Administrators, Remote Desktop Users).
    *   Requires administrative privileges.
    *   Example: `net localgroup Administrators John /add`

2.  **Remove a user from a local group:**
    ```bash
    net localgroup <groupname> <username> /delete
    ```
    *   Removes the specified user account from the specified local group.
    *   Requires administrative privileges.
    *   Example: `net localgroup "Remote Desktop Users" John /delete` (Use quotes if group name has spaces)

### Notes: `net accounts` Command (Windows)

**Purpose:**
The `net accounts` command is used to view and modify the **user account database policies** on the local computer. This includes settings related to password requirements and account lockout behavior for *all* user accounts.

**Common Syntax & Uses:**

1.  **View current policy settings:**
    ```bash
    net accounts
    ```
    *   Displays the current settings for:
        *   Password policy (minimum/maximum age, minimum length, history length)
        *   Account lockout policy (threshold, duration, observation window)
        *   Forcibly disconnect users when logon hours expire
        *   Role (e.g., Primary, Backup, Workstation)

2.  **Modify policy settings (Examples):**
    *(Requires administrative privileges)*
    *   **Set minimum password length:**
        ```bash
        net accounts /minpwlen:<length>
        ```
        *   Example: `net accounts /minpwlen:8`
    *   **Set maximum password age (days):**
        ```bash
        net accounts /maxpwage:<days>
        ```
        *   Use `UNLIMITED` for no expiration. Example: `net accounts /maxpwage:90`
    *   **Set minimum password age (days):**
        ```bash
        net accounts /minpwage:<days>
        ```
        *   Prevents users from changing passwords too frequently. Example: `net accounts /minpwage:1`
    *   **Set password history count:**
        ```bash
        net accounts /uniquepw:<number>
        ```
        *   Remembers previous passwords to prevent reuse. Example: `net accounts /uniquepw:5`
    *   **Set account lockout threshold:**
        ```bash
        net accounts /lockoutthreshold:<number>
        ```
        *   Number of failed logon attempts before lockout. Use `0` or `NEVER` to disable. Example: `net accounts /lockoutthreshold:5`
    *   **Set account lockout duration (minutes):**
        ```bash
        net accounts /lockoutduration:<minutes>
        ```
        *   How long an account stays locked out. Example: `net accounts /lockoutduration:30`
    *   **Set lockout observation window (minutes):**
        ```bash
        net accounts /lockoutwindow:<minutes>
        ```
        *   Time window during which failed attempts are counted towards the threshold. Example: `net accounts /lockoutwindow:30`

**Context & Relevance (Cybersecurity):**

*   **Reconnaissance/Enumeration:** Running `net accounts` without parameters reveals the system's password and lockout policies, indicating its security posture (e.g., weak password length requirements, no lockout policy).
*   **System Hardening:** Administrators use `net accounts` with parameters to enforce stronger password requirements and configure account lockout to mitigate brute-force attacks.
*   **Potential Misuse:** An attacker with administrative privileges could potentially use `net accounts` to *weaken* security policies (e.g., disable lockout, reduce minimum password length), although this is often a noisy action.

**Important Note:** Viewing current policies (`net accounts`) may be possible for standard users, but **modifying any policy settings requires Administrator privileges**. Changes affect *all* user accounts on the local machine (unless overridden by Group Policy in a domain environment).

---

### Notes: Linux User & Group Management Commands

**Purpose:**
Linux uses a suite of commands (often part of `shadow-utils` or similar packages) to manage local users, groups, and their associated policies, analogous to the `net` commands in Windows.

**User Management Commands:**

1.  **List all local user accounts:**
    ```bash
    cut -d: -f1 /etc/passwd
    # or
    awk -F: '{ print $1 }' /etc/passwd
    # or (often preferred as it includes non-local sources if configured)
    getent passwd | cut -d: -f1
    ```
    *   Parses the `/etc/passwd` file (or name service database) to list usernames.

2.  **View details of a specific user:**
    ```bash
    id <username>
    ```
    *   Shows UID, GID, and group memberships.
    ```bash
    getent passwd <username>
    ```
    *   Shows the user's entry from the password database (UID, GID, home dir, shell).
    ```bash
    chage -l <username>
    ```
    *   Shows password aging information (last change, expires, inactive). Requires root/sudo for details on others.

3.  **Add a new user account:**
    ```bash
    sudo useradd <username>
    # Optionally set home directory, shell, groups etc. with flags
    # Example: sudo useradd -m -s /bin/bash -G developers newuser

    # Then set the password:
    sudo passwd <username>
    ```
    *   `useradd` creates the account. `passwd` sets the initial password interactively.
    *   `adduser` (Debian/Ubuntu) is a higher-level, more interactive script.

4.  **Delete a user account:**
    ```bash
    sudo userdel <username>
    # To also remove the user's home directory and mail spool:
    sudo userdel -r <username>
    ```
    *   Removes the user account. Use `-r` with caution.

5.  **Change a user's password:**
    ```bash
    # As root/sudo to change any user's password:
    sudo passwd <username>

    # As a regular user to change their own password:
    passwd
    ```

**Group Management Commands:**

1.  **List all local groups:**
    ```bash
    cut -d: -f1 /etc/group
    # or
    getent group | cut -d: -f1
    ```
    *   Parses `/etc/group` or the name service database.

2.  **View details/members of a specific group:**
    ```bash
    getent group <groupname>
    # or
    grep "^<groupname>:" /etc/group
    ```

3.  **Add a new group:**
    ```bash
    sudo groupadd <groupname>
    ```

4.  **Delete a group:**
    ```bash
    sudo groupdel <groupname>
    ```

5.  **Add a user to a group:**
    ```bash
    sudo usermod -aG <groupname> <username>
    # The -a (append) is crucial, otherwise user is REMOVED from other secondary groups!
    # Alternative:
    sudo gpasswd -a <username> <groupname>
    ```
    *   Adds an *existing* user to an *existing* group as a secondary group.

6.  **Remove a user from a group:**
    ```bash
    sudo gpasswd -d <username> <groupname>
    # Alternative on Debian/Ubuntu:
    # sudo deluser <username> <groupname>
    ```

**Account & Password Policy Management:**

*   **Viewing Policy:**
    *   Per-user policy: `sudo chage -l <username>`
    *   System-wide defaults: Check `/etc/login.defs` (password aging, UID/GID ranges) and PAM configuration files (e.g., `/etc/pam.d/common-password`, `/etc/pam.d/system-auth`) for complexity, history, etc.
*   **Modifying Policy:**
    *   Per-user policy: `sudo chage [options] <username>`
        *   Example (Max password age 90 days): `sudo chage -M 90 <username>`
        *   Example (Min password age 1 day): `sudo chage -m 1 <username>`
        *   Example (Warn 7 days before expiry): `sudo chage -W 7 <username>`
    *   System-wide defaults: Edit `/etc/login.defs` and relevant PAM configuration files (more complex, requires understanding PAM).
*   **Account Lockout:** Typically configured via PAM modules like `pam_tally2` or `pam_faillock`. Configuration involves editing files in `/etc/pam.d/`. There isn't a single command like `net accounts /lockoutthreshold`.

**Context & Relevance (Cybersecurity):**

*   **Reconnaissance/Enumeration:** Listing users (`getent passwd`), groups (`getent group`), checking group memberships (`id <user>`), and password policies (`chage -l`, `/etc/login.defs`) helps understand the system structure and potential weaknesses.
*   **Privilege Escalation/Persistence:** Adding users (`useradd`), modifying passwords (`passwd`), adding users to privileged groups like `sudo` or `wheel` (`usermod -aG sudo <user>`), or modifying user shells can be used to gain or maintain elevated access.
*   **System Hardening:** Administrators use these commands (`chage`, editing `/etc/login.defs`, configuring PAM) to enforce strong password policies and potentially account lockout to secure the system.

**Important Note:** Almost all commands that modify users, groups, or system policies require **root privileges** (run directly as root or using `sudo`). Viewing information (`id`, `getent`, `groups`) is generally allowed for standard users, though `chage -l` might show less detail for other users if run without `sudo`.

---

## Important Linux Credential & Configuration Files

These files are critical for user authentication and privilege management in Linux:

1.  **`/etc/passwd`**:
    *   **Content:** User account information (username, UID, GID, home directory, default shell).
    *   **Password Field:** Contains an 'x' or '*' indicating the actual hash is in `/etc/shadow`.
    *   **Permissions:** Generally world-readable (readable by all users).

2.  **`/etc/shadow`**:
    *   **Content:** Securely stores user password hashes and password aging information.
    *   **Permissions:** Readable only by the **root** user. This is the primary target file for password cracking attempts (requires root access to obtain).

3.  **`/etc/group`**:
    *   **Content:** Defines groups and lists their members (primary group membership is defined in `/etc/passwd`).
    *   **Permissions:** Generally world-readable.

4.  **`/etc/sudoers`**:
    *   **Content:** Defines which users and groups are allowed to execute commands with **root privileges** (or as other users) using the `sudo` command. Specifies *which* commands they can run.
    *   **Permissions:** Should be readable only by root.
    *   **Editing:** **Crucially**, this file should *only* be edited using the `visudo` command, which performs syntax checking before saving to prevent locking users out of `sudo`.

---

## File Permissions and Ownership

Both Linux and Windows use permissions and ownership to control access to files and directories.

**Linux:**

*   **Model:** Uses a User/Group/Other (UGO) model with Read/Write/Execute (RWX) permissions. Each file/directory has an owning **User** and an owning **Group**. Permissions are defined separately for the User, the Group, and Others (everyone else).
*   **Checking Permissions:**
    ```bash
    ls -l <filename_or_directory> # Long listing shows permissions
    ls -ld <directoryname>        # Shows permissions of the directory itself
    ```
*   **Understanding `ls -l` Output & Symbolic Notation (`rwx`):**
    The first part of the `ls -l` output shows the file type and permissions, e.g., `-rwxr-x---`:
    *   **First character:** File type (`-`=file, `d`=directory, `l`=link, etc.).
    *   **Characters 2-4:** Permissions for the **User (Owner)**.
    *   **Characters 5-7:** Permissions for the **Group**.
    *   **Characters 8-10:** Permissions for **Others**.
    *   **Permission Meanings:**
        *   `r` (Read):
            *   File: Allows viewing the file's contents.
            *   Directory: Allows listing the contents of the directory (filenames).
        *   `w` (Write):
            *   File: Allows modifying or deleting the file's contents.
            *   Directory: Allows creating, deleting, or renaming files *within* the directory (requires `x` as well).
        *   `x` (Execute):
            *   File: Allows running the file as a program or script.
            *   Directory: Allows entering (changing into) the directory (`cd`) and accessing files/subdirectories inside it (requires `r` to list them).
        *   `-`: Indicates the permission is *not* granted.

*   **Understanding Octal Notation (e.g., `777`, `644`):**
    This is a shorthand way to represent the `rwx` permissions for User, Group, and Other using numbers.
    *   **Mapping:** `r` = 4, `w` = 2, `x` = 1, `-` = 0.
    *   **Calculation:** Sum the values for each category (User, Group, Other) separately.
        *   `rwx` = 4 + 2 + 1 = **7**
        *   `rw-` = 4 + 2 + 0 = **6**
        *   `r-x` = 4 + 0 + 1 = **5**
        *   `r--` = 4 + 0 + 0 = **4**
        *   `-wx` = 0 + 2 + 1 = **3**
        *   `-w-` = 0 + 2 + 0 = **2**
        *   `--x` = 0 + 0 + 1 = **1**
        *   `---` = 0 + 0 + 0 = **0**
    *   **Examples:**
        *   `777`: `rwxrwxrwx` - Everyone can read, write, and execute. (Generally insecure).
        *   `755`: `rwxr-xr-x` - Owner has full permissions; Group and Others can read and execute. (Common for directories and programs).
        *   `644`: `rw-r--r--` - Owner can read and write; Group and Others can only read. (Common for regular files).
        *   `600`: `rw-------` - Only the Owner can read and write. (Common for private files/keys).

*   **Changing Permissions (`chmod`):** Requires ownership or root privileges.
    *   **Symbolic Notation:** `u` (user), `g` (group), `o` (other), `a` (all); `+` (add), `-` (remove), `=` (set exactly); `r`, `w`, `x`.
        ```bash
        sudo chmod u+w filename      # Add write permission for owner
        sudo chmod g-rx filename     # Remove read/execute for group
        sudo chmod o=r filename      # Set others to read-only
        sudo chmod a+x filename      # Add execute for all
        sudo chmod -R g+w directory  # Recursively add group write to directory contents
        ```
    *   **Octal Notation:** Use the calculated three-digit number.
        ```bash
        sudo chmod 754 filename      # Sets rwxr-xr--
        sudo chmod 600 filename      # Sets rw-------
        sudo chmod 777 filename      # Sets rwxrwxrwx (Use with caution!)
        ```
*   **Changing Ownership (`chown`, `chgrp`):** Requires root privileges.
    ```bash
    # Change owner
    sudo chown <new_owner> <filename_or_directory>
    # Change group
    sudo chgrp <new_group> <filename_or_directory>
    # Change owner and group simultaneously
    sudo chown <new_owner>:<new_group> <filename_or_directory>
    # Recursively change ownership
    sudo chown -R <new_owner>:<new_group> <directory>
    ```

**Windows:**

*   **Model:** Uses Access Control Lists (ACLs), which are more granular. Each file/folder has an ACL containing Access Control Entries (ACEs). Each ACE specifies a user/group (trustee) and their specific permissions (allow/deny).
*   **Checking Permissions:**
    *   **GUI:** Right-click file/folder -> Properties -> Security tab.
    *   **Command Line (`icacls`):**
        ```cmd
        icacls <filename_or_directory>
        ```
        *   Shows trustees and permissions like (F)ull, (M)odify, (RX)Read & Execute, (R)ead, (W)rite.
*   **Changing Permissions (`icacls`):** Requires ownership or Administrator privileges.
    *   **Granting Permissions:**
        ```cmd
        icacls <file> /grant <user_or_group>:(<perms>)
        # Example: Grant 'Users' Modify permission
        icacls C:\data\myfile.txt /grant Users:(M)
        # Example: Grant 'Sales' group Read & Execute recursively
        icacls C:\data /grant Sales:(OI)(CI)(RX)
        ```
        *   `(OI)` = Object Inherit, `(CI)` = Container Inherit (for recursion)
    *   **Denying Permissions:** (Deny overrides Allow - use carefully)
        ```cmd
        icacls <file> /deny <user_or_group>:(<perms>)
        # Example: Deny 'Guest' Write permission
        icacls C:\data\myfile.txt /deny Guest:(W)
        ```
    *   **Removing Permissions:**
        ```cmd
        icacls <file> /remove <user_or_group>
        # Example: Remove all explicit permissions for 'Guest'
        icacls C:\data\myfile.txt /remove Guest
        ```
    *   **GUI:** Use the "Edit" or "Advanced" buttons on the Security tab.
*   **Changing Ownership:** Requires Administrator privileges.
    *   **Taking Ownership (`takeown`):** Makes the current administrator the owner.
        ```cmd
        # Take ownership of a file
        takeown /f <filename>
        # Take ownership of a directory recursively
        takeown /f <directory> /r /d y
        ```
    *   **Setting Owner (`icacls`):** Sets a specific user/group as owner.
        ```cmd
        icacls <file_or_directory> /setowner <user_or_group>
        # Example: Set 'Administrators' as owner recursively
        icacls C:\data /setowner Administrators /t /c
        ```
        *   `/t` = recursive, `/c` = continue on errors.
    *   **GUI:** Properties -> Security -> Advanced -> Owner -> Change.


