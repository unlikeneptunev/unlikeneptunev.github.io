---
title: "FindIT CTF 2026"
date: 2026-05-3
platform: findit26
category: [forensics, misc]
---

# Foren: debris [100 pts]
## Description
A disk image from a researcher’s workstation was recovered during an investigation. Examine the image and determine what was left behind.

Author: gorbaz

## Solution
In this challenge, you are given an image file named `chall.img`, which turns out to be a Linux filesystem, as evidenced by its folder structure: `/home/researcher`. When opened with FTK Imager, in `/home/researcher`, there is a `.bash_history` file whose contents, well, match the filename. There are four commands there.

![debris_1](/images/writeups/findit26/debris_1.png)

From the bash history, there is a zip file created with a password derived from `.session_key`, which was then immediately deleted. The file that was zipped is `keep.jpg`. The deleted files are empty, meaning the files have been completely unlinked from the filesystem.

Since this involves a missing file, I tried using **[Foremost](https://www.kali.org/tools/foremost/)** to recover it, and there was a ZIP file there.

![debris_2](/images/writeups/findit26/debris_2.png)

The decompression process asked for a password. I used the one in the `.session_key` file, which is `jp3gm4f14`. The contents were a `keep.jpeg` file, which is a regular JPEG.

![debris_3](/images/writeups/findit26/debris_3.png)

Here, the image file is just white. I had a hunch that this might be steganography. I went straight to **[Aperi'Solve](https://www.aperisolve.com/)**.

Now, what’s interesting here is the result from steghide, which actually produced a `flag.txt` file. I tried downloading the result.

![debris_4](/images/writeups/findit26/debris_4.png)

What you’ll download is a 7z archive. Extract it, `cat flag.txt`, and you’ll get the flag.

## Flag
```
FindITCTF{h4v3_y0u_7r13d_c4rv1ng}
```
