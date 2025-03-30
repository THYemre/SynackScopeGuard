# SynackScopeGuard

**SynackScopeGuard** is a tool designed to help Synack Red Team researchers avoid accidentally interacting with out-of-scope (OOS) assets during testing. By monitoring network traffic, the script notifies the user when traffic is detected to OOS assets, and can trigger a kill switch to prevent further interactions with such assets. This ensures researchers stay within the scope and avoid being banned from the platform.

## Features

- **Monitor Network Traffic**: Continuously monitors the network traffic for interactions with IP addresses or hostnames.
- **Automatic IP Resolution**: Resolves provided hostnames to IP addresses for real-time monitoring.
- **Wildcard Support**: Supports wildcard patterns (e.g., `*.google.*`) for flexible asset matching.
- **Exclusion List**: Allows excluding certain IP addresses from monitoring.
- **Kill Switch**: Triggers a kill switch (disables network adapter) if traffic to out-of-scope assets is detected, preventing further interaction.
- **Notification System**: Prints detailed notifications, including hostname and packet details, when out-of-scope traffic is captured.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SynackScopeGuard.git
   cd SynackScopeGuard
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make sure you have the necessary permissions to run the kill switch commands (e.g., running the script with `sudo` on Linux/macOS).

## Usage

### Basic Monitoring:

To start monitoring traffic to the provided hostnames, run the script with the hostname file:

```bash
python synack_scope_guard.py -f hostnames.txt
```

Where `hostnames.txt` contains a list of hostnames you want to monitor, one per line. The script will automatically resolve these hostnames to IP addresses and begin monitoring traffic.

### Excluding IPs:

To exclude certain IP addresses from monitoring, provide an exclusion list file using the `-e` option:

```bash
python synack_scope_guard.py -f hostnames.txt -e exclude_ips.txt
```

Where `exclude_ips.txt` contains the IP addresses to exclude, one per line.

### Kill Switch:

Enable the kill switch (to disable network interface) if out-of-scope traffic is detected:

```bash
python synack_scope_guard.py -f hostnames.txt -k
```

### Generating IP List:

To generate an `ip_list.txt` from a list of hostnames, use the `-g` option:

```bash
python synack_scope_guard.py -g hostnames.txt
```

This will resolve the hostnames in `hostnames.txt` to IP addresses and save them to `ip_list.txt`.

### Custom Kill Switch Trigger Count:

You can set a custom packet count threshold for when the kill switch should be triggered:

```bash
python synack_scope_guard.py -f hostnames.txt -k -c 10
```

This will trigger the kill switch after 10 packets are captured to out-of-scope assets.

### Reverse DNS Lookup:

The script performs reverse DNS lookup to match hostnames against wildcard patterns. If a packet's destination matches an out-of-scope asset, the script will notify the user and, if configured, trigger the kill switch.

## Example Output:

```bash
[*] Capturing all traffic to IPs: 1.1.1.1, 1.1.1.2 ...
[*] Excluding traffic to IPs: 1.1.1.1, 1.1.1.1 ...
Packet captured to 172.117.11.112 (hostname-google.com)
Packet count for 172.117.11.112: 5
<REGEX MATCH !!> Hostname google.com matches the pattern *.google.*
Kill switch triggered after 5 packets to google.com.
[*] Network interface eth0 has been disabled.
```
## Running at Startup

To ensure that **SynackScopeGuard** runs automatically when your computer starts, you can add it to your system's startup process. Below are instructions for both Windows and Linux.

### Windows

1. Press `Win + R`, type `shell:startup`, and hit `Enter`. This opens the Startup folder.
2. Create a shortcut to the Python script in this folder:
   - Right-click in the Startup folder and select **New > Shortcut**.
   - In the **Type the location of the item** field, enter the following command:
     ```bash
     python C:\path\to\SynackScopeGuard\synack_scope_guard.py -f C:\path\to\hostnames.txt
     ```
   - Replace `C:\path\to\SynackScopeGuard\synack_scope_guard.py` with the full path to your Python script, and `C:\path\to\hostnames.txt` with the path to your hostnames file.
3. Click **Next**, name the shortcut (e.g., "SynackScopeGuard"), and click **Finish**.

This will ensure that the script runs each time your computer starts up.

### Linux

1. Open a terminal and type the following to open the crontab editor:
   ```bash
   crontab -e
   ```

2. Add the following line at the end of the crontab file to run the script at startup:
   ```bash
   @reboot /usr/bin/python3 /path/to/SynackScopeGuard/synack_scope_guard.py -f /path/to/hostnames.txt
   ```
   - Replace `/path/to/SynackScopeGuard/synack_scope_guard.py` with the full path to your Python script.
   - Replace `/path/to/hostnames.txt` with the path to your hostnames file.
   
3. Save and close the crontab file. The script will now run automatically when your Linux machine boots up.


## Disclaimer

This tool is intended for use on the Synack Red Team platform or other environments where you have explicit permission to test. Unauthorized use may violate the platform's terms of service or the law.

The name **SynackScopeGuard** reflects its purpose of guarding the scope of Synack Red Team engagements by preventing interactions with out-of-scope assets. The README provides clear usage instructions, features, and installation steps to help users get started quickly and understand the functionality of the script. Let me know if you'd like to make any adjustments!
