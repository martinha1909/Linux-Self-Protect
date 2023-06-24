# Fanotify

FanotifyEvents is a component of the project that utilizes `fanotify` to report file system events. 

This component uses 2 different groups of `fanotify`, the permission group (i.e `FAN_CLASS_CONTENT`) and the notification group (i.e `FAN_CLASS_NOTIF`) to report different types of tampering events. 

Upon service startup, 2 threads will start and listen for different types of events in parallel.

## The Permission Thread

Permission thread is responsible for handling read and open events

<b>Initialization</b>

- Upon startup, a thread will initalize by doing the following:
1. Initialize `fanotify` permission group by passing `FAN_CLASS_CONTENT` to `fanotify_init`. 
2. Proper masks are passed to `fanotify_mark` to indicate which permission events should be reported by using bitwise OR operation. Currently, the following masks are used to report read and open events:
    - `FAN_ACCESS_PERM`

<b>Events Detected</b>

The following order of actions will occur when an event is detected
1. For permission group, `fanotify` requires the calling application to write back a response. Hence, the service will default to block the action first by sending `FAN_DENY`.
2. Token verification process starts
3. In the case of authorized access, grace period will start and any actions will result in the service sending `FAN_ALLOW` as a response instead.

## The Notification Thread

Notification thread is responsible for handling delete, create, modify, and attribute change events

<b>Initialization</b>

- Upon startup, a thread will initialize by doing the following:
1. Initialize `fanotify` permission group by passing `FAN_CLASS_NOTIF` to `fanotify_init`.
    - In the case of delete and create events, information on which files or directories have been deleted or created, the following masks were also added by OR-ing with `FAN_CLASS_NOTIF`:
        - `FAN_REPORT FID`
        - `FAN_REPORT_DFID_NAME`
2. Proper masks are passed to `fanotify_mark` to indicate which notification events should be reported by using bitwise OR operation. Currently, the following masks are used:
    - `FAN_CREATE`
    - `FAN_DELETE`
    - `FAN_CLOSE_NOWRITE`
    - `FAN_CLOSE_WRITE`
    - `FAN_MOVED_FROM`
    - `FAN_MOVED_TO`
    - `FAN_ATTRIB`
    - `FAN_ONDIR`

<b>Events Detected</b>

Since `fanotify` notification group is merely informative, the tampering actions in this group cannot be blocked by `fanotify`. Hence, unauthorized access is blocked manually. 

The following order of actions will occur when an event is detected
1. The reported actions from `fanotify` will be stored into memory by `FileManager`. 
2. According to which action was reported, `FileManager` will revert those actions
3. Token verification process starts
4. In the case of authorized access, all events during grace period will only be informative and no actions will be done.
