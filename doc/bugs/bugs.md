# Known Bugs
1. Intermitten failure of multiple events in one command.
- When a command is issued with multiple objects, `mkdir dir1 dir2` for example, will result in the 2nd object not being caught by our service, but that object is still marked. Hence, performing any actions on that uncaught object results in the service crash. 
- Although this bug is not investigated, it seems that doing the following steps could reproduce the bug:
    1. run a notification event command, delete event for example.
    2. Enter the correct token
    3. Run a permission event (i.e read or open) during the grace period
    4. Wait for grace period to be done, then run a command with multiple objects

2. Add record in query history for attempting to stop or uninstallation of service
- Currenty the service only blocks actions to stop or uninstall the daemon, but does not post records of these attempts to history

3. Protects our executable binaries under `/usr/bin` directoy from being tampered with

4. Report execute events on binary files
- Currently if a malicious actor tries to execute a binary file under the protected directory, it is not blocked. 
- This can be done by adding `FAN_OPEN_EXEC_PERM` into `fanotify` permission group

5. Creating a new directory under a protected directory with multiple levels does not work
- When creating a single sub-directory, our service will be able to properly update the memory once the token has been entered correctly. However, if multiple levels of the sub-directory are created such as `mkdir -p sub_dir1/sub_dir2/sub_dir3`, only the top most parent level of the sub-directory is added to memory (`sub_dir1` in this case). Please note that this is the same for multiple levels of files being created, `mkdir -p sub_dir1/sub_file.txt`
- This can be done by querying the contents of the newly created sub-directory in `storeNewChanges()` function in `FileManager`

6. Move to events when token is entered incorrectly results in data loss
- When an object is moved from a non-protected directory to a protected directory (reported by `FAN_MOVED_TO`), the service will store it in memory and revert the changes. If the token is entered incorrectly, the service will not allow that object to be moved to the protected directory and will result in that object being deleted due to the move command. 

7. Permission events are allowed shortly after service was attempted to stop
- There is a small window in which if a service was attempted to stop, the daemon child process will restart the daemon but leaving a 1 or 2 second window where protected files can be viewed. This does not happen for notification events since during initialization we make all protected directories and files immutable.

8. Intermitten failure for terminal to prompt upon an event after OS startup
- The service is configured to start by `systemd` upon OS startup, but when an event occurs, we see that they are blocked but the terminal isn't spawning to request a token. Reinstalling the service fixes this issue

9. Trusted processes intermittenly fails
- With a process name that is considered trusted, sometimes a terminal is still prompted and the changes are blocked. Currently, `auditctl` is being used to query which process name is making changes to a protected file system, this is not a good way to implement trusted processes feature
