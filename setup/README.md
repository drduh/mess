# Install

Create directory for application logs:

```bash
sudo mkdir -p /var/log/mess
sudo chown root:staff /var/log/mess
sudo chmod 750 /var/log/mess
```

Create directory for fifo channel:

```bash
sudo mkdir -p /usr/local/var/mess
sudo mkfifo -m 600 /usr/local/var/mess/events.fifo
sudo chown root:wheel /usr/local/var/mess/events.fifo
```

Install [`eventFilter.sh`](eventFilter.sh):

```bash
sudo mkdir -p /usr/local/libexec/mess
sudo cp eventFilter.sh /usr/local/libexec/mess
sudo chown root:wheel /usr/local/libexec/mess/eventFilter.sh
sudo chmod 700 /usr/local/libexec/mess/eventFilter.sh
```

Install [`exec.jq`](exec.jq):

```bash
sudo mkdir -p /usr/local/etc/mess
sudo cp exec.jq /usr/local/etc/mess
sudo chown root:wheel /usr/local/etc/mess/exec.jq
sudo chmod 700 /usr/local/etc/mess/exec.jq
```

Grant eslogger full disk access:

- As an administrator, open System Settings > Privacy & Security > Full Disk Access.
- Select Add, press <kbd>Command</kbd> + <kbd>Shift</kbd> + <kbd>G</kbd> and type `/usr/bin/eslogger`

Install daemons:

```bash
sudo cp local.mess.eslogger.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/local.mess.eslogger.plist
sudo chmod 644 /Library/LaunchDaemons/local.mess.eslogger.plist
sudo cp local.mess.filter.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/local.mess.filter.plist
sudo chmod 644 /Library/LaunchDaemons/local.mess.filter.plist
```

Load daemons:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/local.mess.eslogger.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/local.mess.filter.plist
```

Confirm daemons are loaded:

```console
$ sudo launchctl list | grep local.mess
9998	0	local.mess.filter
9996	0	local.mess.eslogger
```

Check application logs - `filterErr.log` should be empty and `mess-v1-*.log` should be receiving events:

```console
$ ls -l /var/log/mess
...
-rw-r--r--   1 root  staff     0B Sep 13 12:00 esloggerErr.log
-rw-r--r--   1 root  staff     0B Sep 13 12:00 filter.log
-rw-r--r--   1 root  staff     0B Sep 13 12:00 filterErr.log
-rw-r-----   1 root  staff     3K Sep 13 12:00 mess-v1-macbook-20260913120000.log
```
