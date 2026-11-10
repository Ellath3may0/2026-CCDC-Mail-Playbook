# Mega Script

## Information

This is a startup script for the 2026 mail service box. This box runs on Ubuntu and is required to run postfix and dovecot (smtp, pop3, and imap), rouncube webmail, an ssh server, and should authenticate for those services exclusively via active directory, either via ldap or kerberos (It should account for both). The script reports the current step and a progress bar/time estimate for each task.

## Requirements

ignore bash profile configuration entirely. Unset all aliases, potentially malicious environment variables, all of it.
require sudo
erase prompt command of 'sysadmin' and 'root'
remove all bashrc and profile files for root and sysadmin and replace them with ubuntu default ones
change current user's password
change root password
kill all other open shell sessions (who && pkill)
run `sudo apt update && sudo apt install fish`
set root user's shell to fish
run `sudo apt upgrade` in the background without sending the output to the command line (prioritise kernel updates, service updates that fix vulnerable services (PHP for example), mandatory system)
pull the nftbuild script [linked here](https://tinyurl.com/nftbuild) (do this in parallel and merge back into the main process when finished) and run it: `nftbuild -sys mail -ssh ei`
nuke all tools that could give a threat actor remote access to the system that aren't scored (ssh, postcot, dovecot, roundcube, and the kerberos client are scored)
check bootloader for tampering (if there is any, fix it. if it can't be fixed, inform the user)
check/fix all file/folder permissions/owners (/etc, /root, home directories, etc. etc.) (use the principles of zero trust and least privilege to their fullest extents)
nuke snap
run a binary integrity check on necessary binaries
sysctl hardening
scan for potential issues in service configurations/setups
remove all temporary files
stop any processes that are in memory but not on the disk
perform a system daemon reload
Output to the terminal the completion status of the apt upgrade background task, and if the task isn't finish, return its output to the command line so the user knows what is going on.
