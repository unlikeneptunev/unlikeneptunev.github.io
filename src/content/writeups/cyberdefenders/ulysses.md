---
title: "Ulysses"
date: 2026-09-08
platform: cyberdefenders
tags:
  [
    initial access,
    execution,
    persistence,
    privilege escalation,
    command and control,
    exfiltration,
    impact
  ]
difficulty: medium
tools: [vs code, ftk imager, autopsy, volatility, 010 editor]
---

### Scenario
A research server was flagged for suspicious activity after multiple failed authentication attempts. Analysts detected a brute-force attack, unauthorized outbound connections, and possible persistence mechanisms. Using Volatility, a custom Debian5_26 profile was loaded to analyze memory dumps and identify malicious processes. Your task is to investigate forensic artifacts, determine the attacker's entry point, and uncover any deployed payloads.

### Question 1: The attacker was performing a Brute Force attack. What account triggered the alert?

Brute-force mean that a user was trying to log in by submitting different combinations of username and password. We can check `auth.log` on `/var/log` directory.

![q1](/images/writeups/ulysses/q1.png)

From the screenshot alone, we can tell that the user `ulysses` was the culprit, by failed to log in (wrong password) repeatedly in quick succession.

### Question 2: During investigating the logs. How many failed login attempts were alerted by the same user?

**Answer 32**

Opening the log file again in a text editor and look for patterns like the keyword "Failed". There, we can found 32 failed login attempts from the user `ulysses`, though it also includes the default `Failed none ...` log from SSH itself.

### Question 3: What kind of system runs on the targeted server?

**Answer: Debian GNU/Linux 5.0**

Linux distro name commonly stored in `/etc/os-release` or `/etc/issue`, but apperantly the first one does not exist in the image. So, we can see if `issue` exist.

![q2](/images/writeups/ulysses/q2.png)

As we can see in FTK Imager above, the `issue` file tells us that the target machine is using Debian GNU/Linux 5.0.

### Question 3: What is the victim's IP address?

**Answer: `192.168.56.102`**

There's no way that we can access the target's console and do `ip a` in order to get the IP address. However, we can get it from the file `dhclient.eth0.leases` in `/var/lib/dhcp3`. That file contains all IP addresses assigned by the DHCP server.

```bash

lease {
  interface "eth0";
  fixed-address 10.0.2.15;
  filename "Victoria.pxe";
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 86400;
  option routers 10.0.2.2;
  option dhcp-message-type 5;
  option dhcp-server-identifier 10.0.2.2;
  option domain-name-servers 192.168.1.1,192.168.1.1;
  option domain-name "home";
  renew 0 2011/02/06 12:03:38;
  rebind 0 2011/02/06 12:03:38;
  expire 0 2011/02/06 12:03:38;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 12:31:12;
  rebind 0 2011/02/06 12:57:11;
  expire 0 2011/02/06 13:04:41;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 12:54:43;
  rebind 0 2011/02/06 13:23:42;
  expire 0 2011/02/06 13:31:12;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 13:20:26;
  rebind 0 2011/02/06 13:47:13;
  expire 0 2011/02/06 13:54:43;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 13:47:50;
  rebind 0 2011/02/06 14:12:56;
  expire 0 2011/02/06 14:20:26;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 14:10:22;
  rebind 0 2011/02/06 14:40:20;
  expire 0 2011/02/06 14:47:50;
}
lease {
  interface "eth0";
  fixed-address 192.168.56.102;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 3600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.56.100;
  renew 0 2011/02/06 14:34:17;
  rebind 0 2011/02/06 15:02:52;
  expire 0 2011/02/06 15:10:22;
}
```

Looking at the full content, `192.168.56.102` appeared 6 times which is dominant, representing the IP used by the time of the incident.