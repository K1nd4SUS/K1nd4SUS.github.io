---
layout: /src/layouts/MarkdownPostLayout.astro
title: (misc) K!nd4SUS CTF 2025 Writeups
author: K!nd4SUS
description: "Writeups for K!nd4SUS CTF '25 (misc). Check the other categories on the website!"
pubDate: 2024-03-17
tags: ["writeup", "K!nd4SUS2025", "competition", "CTF", "misc"]
image:
  url: "/images/writeup/bannermisc.webp"
  alt: "CTF"
languages: ["python"]
---

## Misc Writeups
---

### Talking to the Void
On a unix system, what the users are doing is visible to other users.
The w command is our target.
It will be a prefix of step() on average once every 64 attempts.
A partial solution is to spam shell 1, but the answer would not be understandable.
Fortunately, _memory never sees the original (empty) _state.
So reset() will not intercept seed="".
Therefore, we can travel back in time by sending reset without arguments when we see a good answer with step.
To avoid long runs, we can reset the internal secret after every step, triggering a hard reset with reset.
Note: Due to difficulties in making w work in a container the actual script on the server had a modified run().
The modified function intercepts the first argument w and gives the correct answer.
To account for unintended solution the actual run() is called in all the other cases.
EDIT: The original script had a bug that could compromise the availability of the challenge.
Therefore it had to be patched during the competition (there were surely better fix that retained the unintended solution but I wasn't able to implement them at the time). Sorry about that.
Waiting for sh instead of w provided a blind remote shell, this was because the input parameter for run() was not set.

```python
from subprocess import Popen, PIPE
from base64 import b64decode
from time import sleep

cmd = 'python server.py'
process = Popen(cmd
, shell=True, text=True
, stdin=PIPE, stdout=PIPE)

def get_line():
	line = process.stdout.readline()
	if not line and process.poll() is not None:
		exit()
	print(line, end='', flush=True)
	return line

def get_lines():
	while True:
		line = get_line()
		if not line:
			sleep(.1)
		if line.startswith("?"):
			break

def send(query):
	print(query)
	query += "\n"
	process.stdin.write(query)
	process.stdin.flush()

def step():
	send("step")
	sleep(.1)
	ans = get_line().strip()
	return ans

def unscramble(secret, message):
	secret = b64decode(secret)
	message = b64decode(message)
	ans = bytes(x ^ y for x, y in zip(secret, message))
	try:
		ans = ans.decode()
	except:
		ans = str(ans)
	return ans

while True:
	get_lines()
	ans = step()
	if ans.startswith("w"):
		break
	get_lines()
	send("reset " + ans)
secret = ans
get_lines()
send("reset")
get_lines()
send("shell 1")
while True:
	line = get_line().rstrip()
	if not line:
		sleep(3)
		continue
	if line.startswith("?"):
		break
	if '.' not in line and ':' not in line:
		print(unscramble(secret, line))
		get_lines()
		break
get_lines()
assert False
```

---
### Whats in a Nimi
In this challenge, we have a very cryptic text written using strange symbols. By using Google Lens or a similar service, we find many pictures of glyphs, and the images most similar to this one contain the text: "Toki Pona."

Toki Pona (tok: toki pona) is a constructed language (conlang) that has a writing system called sitelen pona (literally "good writing"), which is exactly the same as the one employed here.

We can therefore transliterate the text, obtaining the following:

> mi mute li kulupu ni: jan pi kama sona. mi mute li kama sona e sona pi ilo sona.
> mi mute li tan ma [Italija].
> ni li pona tawa mi mute: mi mute li toki suli e utala sin.
> tan ni ale la mi mute li sitelen kepeken toki pona. toki pona li pona anu seme?
> jan ale li toki e toki pona. sina toki ala toki e toki pona?
> toki pona li toki pali. jan [Sonja] li pali e ni.
> ona meli li tan ma [Kanata]. ona meli li wawa mute.
> mi mute ale li wile kama sona e toki pona. sina wile ala wile kama sona e toki pona?
> sina wile pali e ni: sina tawa sona e toki pona. ni la sina ken lukin e lipu mute.
> len sitelen li ni: nimi pi nanpa pini "lipu tenpo".
> ni li sama e [KSUS]"{" len sitelen "}".
>               tan jan [Samele]

Which might be translated into:

> We are a group of this: students. We study knowledge about knowledge devices (computer science)
> We are from Italy
> This is good/happy for us: we announce a new challenge.
> Because of this all, we write using toki pona. Isn't toki pona good?
> toki pona is a constructed language. Person Sonja works on it.
> She is from Canada. She is very strong.
> We all want to learn toki pona. Do you want to learn toki pona?
> You want to work on this: you learn toki pona. In this context, you can look at several books/publications/papers.
> The written textile/secret (flag) is this: the name of the last edition of "lipu tenpo".
> This is equal to ksus{flag} (uses the format indicated, reasonably).
>               by person Samele (Samuele)

The name of the last edition of the magazine "lipu tenpo" is "nanpa kala". We can try to submit "ksus{nanpa kala}" as the flag.

```ksus{nanpa kala}```

Also accepted with underscores, capital letters, etc.

---
### Cybersecurity, Gamified
Writeup PDF here: https://github.com/K1nd4SUS/KSUSCTF25_Writeups/blob/main/MISC/cybersecurity_gamified.pdf