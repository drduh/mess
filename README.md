# mess: macOS Endpoint Security Signals

Currently in early development and alpha testing.

Observe and investigate activity on your Mac, locally and privately.

- **No privileges required** - Uses built-in macOS authorization to use Apple's kernel-level security framework.
- **Fully local** - No account, no cloud integration, no server anywhere but your own Mac.
- **Efficient and reliable** - Built with Golang without any third party depedencies.

## Overview

`eslogger` captures every program launch straight from Apple's Endpoint Security framework.

A filter distills each event and flags anything unusual.

A single Go program starts a local web server bound only to your own machine (`localhost`).

Open in any browser to use.

## Development

See [Setup](setup/README.md) to configure `eslogger` to log and filter system `exec` events in the background.

Clone the repository, build and run the application:

```bash
make run
```
