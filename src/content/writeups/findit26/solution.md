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

![debris_1](/images/writeups/findit26/debris/debris_1.png)

From the bash history, there is a zip file created with a password derived from `.session_key`, which was then immediately deleted. The file that was zipped is `keep.jpg`. The deleted files are empty, meaning the files have been completely unlinked from the filesystem.

Since this involves a missing file, I tried using **[Foremost](https://www.kali.org/tools/foremost/)** to recover it, and there was a ZIP file there.

![debris_2](/images/writeups/findit26/debris/debris_2.png)

The decompression process asked for a password. I used the one in the `.session_key` file, which is `jp3gm4f14`. The contents were a `keep.jpeg` file, which is a regular JPEG.

![debris_3](/images/writeups/findit26/debris/debris_3.png)

Here, the image file is just white. I had a hunch that this might be steganography. I went straight to **[Aperi'Solve](https://www.aperisolve.com/)**.

Now, what’s interesting here is the result from steghide, which actually produced a `flag.txt` file. I tried downloading the result.

![debris_4](/images/writeups/findit26/debris/debris_4.png)

What you’ll download is a 7z archive. Extract it, `cat flag.txt`, and you’ll get the flag.

## Flag
```
FindITCTF{h4v3_y0u_7r13d_c4rv1ng}
```

# Foren: I wanna go home  [50 pts]
## Description
Good morning, Mom. I hope you’re feeling well today. I’m writing this to let you and the rest of our family know that I might not be able to come home this month. My manager is currently holding me up because he said they observed suspicious activity on my part. Don’t you know how ridiculous that sounds? I’ve been working here for 10 years now and they’re saying I’m turning my back on them! Well, I did something a little naughty a few days ago… you could say I broke a rule of our meeting. But, it’s not supposed to be such a big deal! It’s just a little something and it’s not dangerous at all to the company. If only they’d take a closer look instead of just listening to what everyone says, they’d see it’s nothing serious. They’re going to check on me later—if only I could change everything…. Well, please keep your fingers crossed, Mom; I really hope I can go home this month.

**MD5: 8787a5cafdedb60e799fa840127ea907**

Author: zenapietal

## Solution
Another image file has been provided. This time, it looks like macOS.

![iwgh_1](/images/writeups/findit26/i_wanna_go_home/iwgh_1.png)

![iwgh_2](/images/writeups/findit26/i_wanna_go_home/iwgh_2.png)

Actually, there’s nothing too interesting, except for the `rec_0923.dat` file in the Temp directory. Why? Because its naming format is almost the same as the one in the `Audio` directory, but the extension is different.

![iwgh_3](/images/writeups/findit26/i_wanna_go_home/iwgh_3.png)

After checking the file, it turns out this is an audio file hidden with a `.dat` extension. Just rename it to use an audio extension. Here I’m using `.wav`.

After playing it, I wasn’t sure what to do next. So, since it’s audio, I tried viewing the spectrogram using **[this online tool](https://www.boxentriq.com/steganography/audio-spectrogram)**.

![iwgh_4](/images/writeups/findit26/i_wanna_go_home/iwgh_4.png)

It was a bit confusing to look at. But, at a glance, there was some HEX code there. I tried stretching the image a little and got the following HEX:
```bash
7b77335f773372665f74346c6b316e675f34623075745f6c756e6368217d
```

If converted to a string, the result was this:
```bash
{w3_w3rf_t4lk1ng_4b0ut_lunch!}
```
I tried wrapping it in the flag format, but it turned out to be wrong. It seems there was a typo when I looked at the HEX, so I tried changing one letter to this:
```bash
{w3_w3re_t4lk1ng_4b0ut_lunch!}
```

Well, it turns out to be correct.

## Flag
```
FindITCTF{w3_w3re_t4lk1ng_4b0ut_lunch!}
```
