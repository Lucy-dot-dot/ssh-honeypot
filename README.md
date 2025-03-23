# Honeypot SSH Server

## About

A small SSH server that allows for advanced honeypot usage [0]. This tool provides a fake command interface mimicking Ubuntu without any fear of malicious code execution, since no commands are actually executed. It also records all commands in a central database for later analysis [0].

## Features

- Simulates an Ubuntu-like environment safely
- Logs all attempted commands
- Records authentication attempts (successful and unsuccessful) [2]
- Tracks session information (start time, end time, duration) [2]
- Stores commands and activity in a database for analysis [2]
- Provides fake system file contents (like `/proc/cpuinfo`) [3]

## Usage

```
honeypot-ssh-server [OPTIONS]
```

### Options

- `-i, --interface <ADDRESSES>`: The IP addresses and ports to listen on (default: 0.0.0.0:2222 for IPv4 and [::]:2222 for IPv6) [0]
- `-d, --db <PATH>`: Path to the database file (default: "honeypot.db") [0]

### Environment Variables

- `INTERFACE`: Alternative way to specify the listening interfaces [0]
- `DATABASE_PATH`: Alternative way to specify the database path [0]

## Requirements

- For binding to ports under 1000, you'll need to use the Linux `setcap cap_net_bind_service` command [0]

## Database

The tool records several types of information [2]:
- Authentication attempts (IP, username, password/key, success status)
- Commands entered by attackers
- Session information (duration, start/end times)

## Security Note

This tool is designed to be used as a honeypot for research purposes. It simulates a vulnerable system without actually executing any malicious commands, making it safe to deploy for security research and threat intelligence gathering.

## Legal Disclaimer

This software is provided "as-is" without any warranty or guarantee of any kind, either expressed or implied. The author(s) of this honeypot SSH server are not liable for any damages, attacks, security breaches, data loss, system compromises, or other negative consequences that may arise from using this software.

By installing and using this software, you acknowledge that:

1. You are using this software at your own risk
2. The author(s) bear no responsibility for any security vulnerabilities that may exist in the code
3. The author(s) are not responsible for any attacks directed at your systems as a result of using this software
4. No fitness for a particular purpose is guaranteed
5. The author(s) are not liable for any misuse of the collected data

This tool is intended for security research and educational purposes only. Users are responsible for deploying it in compliance with all applicable laws and regulations in their jurisdiction.