# About the project

SelfProtectService is a daemon process that monitors important files and directories and protects them from being tampered with on Linux using [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html). Currently only Debian based system is supported

For details on how `fanotify` is utilized in this project, please see `src/FanotifyEvents/README.md`

The design of this project can be found under `doc/design`

A list of known bugs can be found under `doc/bugs`

# Prerequisites
## Build
This project can be built using the `build.sh` script under `src/build.sh`. Please note that everything in this build script currently uses <b>relative paths</b>, so the current working directory <b>MUST</b> be under `src/` for this build script to work. 
- Root privilidge is required to build these prerequisites

- What will be installed?
    - `ubuntu-gnome-desktop`
    - `dbus-x11`
    - `curl`
    - `libcurl4-openssl-dev`
    - `libssl-dev`
    - `auditd`

The build script will run `make` once all the dependency packages are installed

# Installation
[](#installation)
- Installation of the project can be done with 2 steps
1. Run the `create_build.sh` under the `installer/` directory 
2. Run `sudo dpkg -i selfprotect_1.0_x86-64.deb`

- Upon installation, the following directories are created
    - `/opt/self_protect`
    - `/opt/self_protect/bin`
By default, files under these 2 directories are protected by the service

- Upon installation, the following binaries are installed
    - `/usr/bin/self_protect`: the daemon of the project, which will start during OS startup
    - `/usr/bin/sysd_service_monitor`: a child process of the daemon, responsible for preventing unauthorized user from stopping or uninstalling the daemon.
    - `/usr/bin/sp_bin_upload`: a script that uploads protected binary files into the cloud.
    - `/opt/self_protect/bin/sp_client`: token authorization process, responsible for spawning a client terminal for a user to enter the token
    - `/opt/self_protect/bin/attempts_history`: attempts history records. Can be run to see past tampering attempts

- Upon startup, a child process called `sysd_service_monitor` is spawned to protect the daemon from being stopped. This process binary is located under `/usr/bin/sysd_service_monitor`
- Additionally, the service will log information to `/var/log/self_protect.log`

# Usage

### <b>Running The Project</b>
There are 2 ways to run the project
- By installing the project. Please see #installation
- By running the project manually:
    1. Run the `build.sh` script under `src/build`
    2. Run the project binary
        ```
            sudo /usr/bin/self_protect
        ```

### <b>The Config List</b>
- A text file located under `/opt/self_protect/config_list` and is empty upon installation
- The config list is an important part of the project as it tells the service which directories to protect
    - Directories can be added as separate entries into the config list (authorization required).
    - Any sub-directories and files under an entry will also be protected
- If the config list is deleted, then only the default directory `/opt/self_protect/` is protected

### <b>Attempts History</b>
- A binary located under `/opt/self_protect/bin/attempts_history`
- The following information will be displayed when run:
    - Date and time
    - Tampering action
    - Tampering locations
    - Whether access was granted
    - Whether grace period is in effect

# Grace Period
- Once a token is attempted correctly, a grace period will be granted for 30 seconds (this can be changed according to needs). During this period:
    - Any changes made on the protected directories will be logged, but authentication is not required
    - Any changes made on the protected directories will update the memory in `FileManager` the backup immediately
    - Any permission events (i.e read and open), will result in the service sending `FAN_ALLOW` to `fanotify`

# Block Period
- Token verification process will fail if:
    - The terminal timeout (60 seconds)
    - The token was input incorrectly 5 times
    - The token terminal was cancelled

- If token verification fails, the service will enter a block period (30 seconds), during which:
    - All files and directories are immutable
    - Any operations are denied immediately and no authorization prompt will occur


# Credentials

### Dropbox file sharing backup server
- The service constantly backs up protected files and directories to Dropbox, which can be logged into by using the following credentials

    ```
    email: selfprotectservice@gmail.com
    password: TeamUnicorn12345
    ```
- The token to transporting backup files and directories to Dropbox refreshes every 4 hours, in order to upload files and directories successfully, the following steps have to be done:
    1. Retrieve the new token by logging into [Dropbox Developer Apps](https://www.dropbox.com/developers) using the credentials above
    2. Click on SelfProtectService
    3. Press the `Generate` button in the OAuth 2 section 
    4. Paste that value into the constant `DROPBOX_API_AUTH_TOKEN` in `src/include/FileTransport.hpp`

### Token Web Server
- A valid token can be retrieved through the [Self Protect Service Token Generator](https://self-protect-token-generator.onrender.com/login)