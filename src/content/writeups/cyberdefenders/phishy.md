---
title: "Phishy"
date: 2026-05-26
category: cyberdefenders
tags: [initial access, execution, c2]
difficulty: medium
tools: [ftk imager, autopsy, registry explorer, db browser, browsinghistoryview, passwordfox, WhatsApp Viewer, Oledump, VirusTotal, HybridAnalysis]
---

# Scenario
A company’s employee joined a fake iPhone giveaway. Our team took a disk image of the employee's system for further analysis. As an SOC Analyst, you are tasked to identify how the system was compromised.

### Question 1: What is the hostname of the victim machine?
**Answer**: `WIN-NF3JQEU4G0T`

Identifying the victim's machine is essential, because with that, we can  correlate forensic findings across network logs, security alerts, and other system artifacts easier. One of the ways to know is through Windows Registry Hive. A Windows Registry Hive is a major logical section of the Windows Registry that contains a specific set of keys, subkeys, and values. Here, we are going to need the `SYSTEM` registry hive.

On FTK Imager, we can go to this path to obtain the hive:

```powershell
C:\Windows\System32\config
```

There, we can see the `SYSTEM` file and then export it to our local directory.

![q1_1](/images/writeups/phishy/q1_1.png)

The next step is parsing the data inside the hive. We can choose [RegRipper](https://github.com/keydet89/RegRipper3.0) to do the job for us, using the command below:

```bash
regripper -r SYSTEM -f system > regripper_system
```

The command with `-r` flag specifies the hive file we want to parse, and `-f` tells RegRipper what profile to use. In this case, we needed the `system` profile. Finally, we write the output to the `regripper_system` file to make analysis easier using text editors.

![q1_2](/images/writeups/phishy/q1_2.png)

After opening the output file in Zed and looking for the important part, in this case like `hostname` or `ComputerName`, we can verify that the hostname of the victim's machine is `WIN-NF3JQEU4G0T`.

### Question 2: What is the messaging app installed on the victim machine?
**Answer**: WhatsApp

On Windows, apps typically installed on `Program Files`, `Program Files (x86)` or `AppData` directory. In both `Program Files` directories, there is no messaging apps at all. So, we can check if `AppData` has anything.

![q2](/images/writeups/phishy/q2.png)

As we can see, we found a `WhatsApp` folder on `AppData\Roaming` directory as the only possible messaging app on the computer. WhatsApp is a popular cross-platform messaging app offered by Meta.
