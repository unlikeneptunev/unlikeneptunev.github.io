---
title: "Injector"
date: 2026-08-30
platform: cyberdefenders
tags:
  [
    initial access,
    execution,
    persistence,
    privilege escalation,
    defense impairment,
    discovery,
  ]
difficulty: medium
tools: [r-studio, ftk imager, autopsy, volatility, registry explorer, regripper]
---

# Scenario

A company’s web server has been breached through their website. Our team arrived just in time to take a forensic image of the running system and its memory for further analysis.

As a SOC Analyst, you are tasked with mounting the image to determine how the system was compromised and the actions/commands the attacker executed.

### Question 1: What is the computer's name?

**Answer: `WIN-L0ZZQ76PMUF`**

We can start by looking for the `SYSTEM` hive in the registry in `Windows\System32\config`. Once we have it, open it with [RegistryExplorer](https://ericzimmerman.github.io/#forensic-tools) and look for the `ComputerName` value in `ControlSet001\Control\ComputerName\ComputerName`.

![q1_1](/images/writeups/injector/q1_1.png)

### Question 2: What is the Timezone of the compromised machine? Format: UTC+0 (no-space)

**Answer: UTC-7**

We can see for the `TimeZone` value in `ControlSet001\Control\TimeZoneInformation` to get the timezone of the compromised machine and look for the `ActiveTimeBias` value to get the timezone offset.

![q2_1](/images/writeups/injector/q2_1.png)

Since the bias is `420` (or `+420`), then the timezone offset is `UTC-7` from 420 : 60 = `7` hours.

### Question 3: What was the first vulnerability the attacker was able to exploit?

**Answer: XSS**

![q3_1](/images/writeups/injector/q3_1.png)

As we know from the `SOFTWARE` hive, the Windows variant is Windows Server 2008. So, it's safe to assume that it uses Apache Web Server to operate as a web server (why? maybe because it is one of the most popular web servers(?)). We can also find `Apache` in the `xampp` directory.

Digging into the Apache directory, we can find the `access.log` file. There, looking for certain keywords (magically) gave us the answer.

![q3_2](/images/writeups/injector/q3_2.png)

### Question 4: What is the OS build number?

**Answer: `6001`**

In the same registry path in `Microsoft\Windows NT\CurrentVersion`, we can find the `CurrentBuildNumber` and `CurrentBuild` value which contains the OS build number.

![q4_1](/images/writeups/injector/q4_1.png)

### Question 5: How many users are on the compromised machine?

**Answer: 4**

Referencing from **[this blog](https://boncaldoforensics.wordpress.com/2018/08/01/4n6-quick-01-windows-users-list-login-count/)**, we can find yet another registry hive called `SAM` which contains the user account information.

Loading it in RegistryExplorer in the path `SAM\Account\Domain\Users\Names`, we can see all 4 users on the machine.

![q5_1](/images/writeups/injector/q5_1.png)

### Question 6: What is the webserver package installed on the machine?

**Answer: XAMPP**

Referring to Question 3, the only webserver-related directory here is `xampp`.

![q6_2](/images/writeups/injector/q6_2.png)

Or, if we want to choose the unusual way (like my initial guess), we can also check stored files for every user, and hope we find some installer somewhere.

![q6_1](/images/writeups/injector/q6_1.png)

### Question 7: What is the name of the vulnerable web app installed on the webserver?

**Answer: DVWA**

Since it is using XAMPP, the vulnerable web app is likely to be installed in the `htdocs` directory. And it fact, it is a Damn Vulnerable Web Application (DVWA).

![q7_1](/images/writeups/injector/q7_1.png)

### Question 8: What is the user agent used in the HTTP requests sent by the SQL injection attack tool?

**Answer: `sqlmap/1.0-dev-nongit-20150902`**

Back to the `access.log`, we can look for some SQLi-related requests, simply by finding some popular SQLi tools. For example, `sqlmap` is probably the most popular one.

![q8_1](/images/writeups/injector/q8_1.png)

As we can see, the user agent used in the HTTP requests sent by `sqlmap` is `sqlmap/1.0-dev-nongit-20150902` to the `/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit` endpoint.

### Question 9: The attacker read multiple files through LFI vulnerability. One of them is related to network configuration. What is the filename?

**Answer: `hosts`**

Local File Inclusion (LFI) is a web security vulnerability where an application uses unvalidated user input to load or execute files stored locally on the server. The common way is the attacker trying to "jump" to a certain file/directory, using patterns like `../../../`.

![q9_1](/images/writeups/injector/q9_1.png)

Looking into the `access.log` (again), we can see the LFI pattern clearly. The attacker is trying to read the `hosts` file, which is a plaintext file that maps domain names to specific IP addresses.

### Question 10: The attacker tried to update some firewall rules using netsh command. Provide the value of the type parameter in the executed command?

**Answer: ``**
