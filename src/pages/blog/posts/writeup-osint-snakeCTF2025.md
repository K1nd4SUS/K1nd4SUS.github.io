---
layout: /src/layouts/MarkdownPostLayout.astro
title: (misc) SnakeCTF2025 - The Real Crypto Master
author: Privitorta
description: "Writeup for SnakeCTF2025 misc (osint) challenge: The Real Crypto Master"
pubDate: 2025-08-30
tags: ["writeup", "SnakeCTF2025", "competition", "CTF", "misc", "osint"]
image:
  url: "/images/writeup/snakectf.webp"
  alt: "CTF"
languages: ["miscellaneous"]
---

**Category:** osint  
**Author:** Federico Bertossi (mrByMax)
 
---
## Description  
> It's common sense that "crypto" stands for "cryptocurrency". With my masterclass you will learn everything you need to be like me! You only need to find me :) <br><br>
> Important: This challenge is a multi-part challenge, also, remember to add { in the right place! <br><br>
> Disclaimer: Organisers' personal websites are out of scope. There's no need to code anything to solve this challenge. Every attack directed to any website with the purpose of solving this challenge is forbidden and will result in a ban. If in doubt, open a ticket!

---

## Writeup

### Analyzing "osint_crypto.zip"
The provided archive `osint_crypto.zip` contains a public .csv file, `expenses.csv`, with a list of various expenses our target has made during March 2025. But the zip archive contains a hidden `.DS_Store` file.

![](/images/writeup/snakeCTF/zipfiles.webp)

Unzipping every file solves the problem easily and we can now see the new file, `.DS_Store`. Reading it with a text editor quickly reveals the username **@bepifrico**. 

![](/images/writeup/snakeCTF/dsstorecontent.webp)

Using the [sherlock](https://github.com/sherlock-project/sherlock) tool with the given username, we discover several accounts, including **Youtube** and **Letterboxd**.

### Youtube channel

![](/images/writeup/snakeCTF/channel.webp)

Youtube looked like an approachable route (I thought about "crypto online courses"... I wasn't supposed to find it this way, but it worked). On the [youtube channel](https://youtube.com/bepifrico/) there is a livestream broadcasting morse code.

![](/images/writeup/snakeCTF/youtubelive.webp)

I managed to write out what I heard and got this:

`... -. .- -.- . -.-. - ..-. ....- -- -- ....- .-. ...-- -.-. .... .---- ....- .-. ----- -. ..- -. --... ...-- ..-. ....- .---- ...-- --... .-. ..- ...- ....-` 

Used a web decoder and this was the first part of the flag:
 
`SNAKECTF4MM4R3CH14R0NUN73F4137RUV4`

Which is clearly referring to the song ["Marechià" by Nu Genea](https://www.youtube.com/watch?v=lg_dFaq1iSo&list=RDlg_dFaq1iSo&start_radio=1), neapolitan singer (and amazing song too)!

![](/images/writeup/snakeCTF/morse.webp)

### Letterboxd profile

The live was about some "film review" and I immediately thought letterboxd kept our next part of the flag. The [letterboxd profile](https://letterboxd.com/bepifrico/) contains a single, easy-to-find review that contains the second part of the flag: 
 
`_1V3_41W4Y5_W4N73D_70_54Y_F14M3_0N}`

![](/images/writeup/snakeCTF/letterboxd.webp)

After merging the two separate parts we got from Youtube and Letterboxd and adding the "snakeCTF{" prefix, we obtain our definitive flag.