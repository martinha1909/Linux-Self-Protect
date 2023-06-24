# FileManager

`FileManager` is responsible for manually blocking `fanotify` notification group events (details please see `FanotifyEvents`). 

## Initialization

Upon service startup, `FileManager` will read entries from <b>the config list</b> and store the following into memory
- Parent protected directory as specified in each entry with their attributes
- Sub-directories (if any) of the parent protected directory with their attributes
- Files under the parent protected directory and sub-directory (if any) along with their content and attributes.

## Events Detected

Only `fanotify` notification group events are reported to `FileManager`. Then actions will vary based on the type of event reported by

### Store Changes Phase

