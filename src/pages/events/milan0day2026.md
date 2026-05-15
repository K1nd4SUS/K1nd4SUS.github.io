---
layout: /src/layouts/EventLayout.astro
title: "Milan0day '26"
pubDate: 2026-02-17
tags: ["conference", "event"]
description: "The second edition of the CyberSecurity conference organized by K!nd4SUS at the University of Milan."
image:
  url: "/images/event/milan0day26banner.webp"
  alt: "Milan0day"
---

## Event

On _May 21st_, 2026, **Milan0Day** returns to Milan, bringing together researchers, security professionals, students, and technology enthusiasts for a full day dedicated to cybersecurity.

**Milan0Day** is designed to foster knowledge exchange, technical depth, and meaningful connections within the information security community. The conference focuses on cutting-edge research, real-world attack techniques, defensive strategies, and emerging security challenges across domains such as _cloud, AI, cryptography, network security, hardware security_, and _critical infrastructure_.

Join us for a day of <u>innovation, research, and collaboration</u> at the heart of Italy’s cybersecurity community!

### Tickets

Get your **free** ticket before it's too late! Click [HERE](https://www.eventbrite.com/e/milan0day-2026-cybersecurity-conference-tickets-1984064435135).

![](/images/event/milan0day26.webp)

## Schedule

| Time          | Session                                                                          |
| ------------- | -------------------------------------------------------------------------------- |
| 09:30 - 10:00 | Doors open and registration                                                      |
| 10:00 - 10:10 | Conference opening and institutional greetings                                   |
| 10:10 - 11:05 | Talk 1 - Weights, Worms, and Wreckage: Attacking the Hidden Layers of AI         |
| 11:05 - 12:00 | Talk 2 - Breaking Pacemaker Authentication with Formal Methods                   |
| 12:00 - 12:15 | Break                                                                            |
| 12:15 - 13:10 | Talk 3 - One Ring 0 to Rule Them All: pwn the Windows Kernel by patching it      |
| 13:15 - 14:15 | Lunch break                                                                      |
| 14:15 - 14:20 | Afternoon session opening                                                        |
| 14:20 - 15:15 | Talk 4 - AI and the Death of Privacy? Navigating New Threats and Modern Defenses |
| 15:15 - 16:10 | Talk 5 - AI governance: Deep dive of the security of LLM                                              |
| 16:10 - 16:20 | Pausa                                                                            |
| 16:20 - 17:00 | Talk 6 - Make the analysis fun again!                                            |
| 17:00 - 17:40 | Talk 7 - Everything in the Cloud looks secure... Until It isn’t                                            |
| 17:45 -       | Closing remarks and end of conference                                            |

## Talks

### Talk 1 - Weights, Worms, and Wreckage: Attacking the Hidden Layers of AI

- Topic: AI Security and Attacks on AI Systems
- Speaker: [Jigyasa Grover](https://www.linkedin.com/in/jigyasa-grover)
- Abstract: Most AI security discussions focus on model outputs, jailbreaks, prompt injection, and unsafe responses. But modern AI systems are pipelines: data ingestion, preprocessing, training, artifact storage, retrieval layers, and inference infrastructure. Each stage introduces its own attack surface. This session examines vulnerabilities across the AI lifecycle, including data poisoning and training-time manipulation, backdoored model artifacts and dependency chain risk, retrieval augmentation abuse and embedding-space manipulation, inference-layer and infrastructure weaknesses, and supply-chain risks in open-source models and tooling. Rather than treating these as isolated exploits, we analyze the systemic conditions that make them possible and the architectural controls that mitigate them. We cover practical safeguards such as dataset integrity validation, artifact signing and provenance tracking, environment isolation, controlled retrieval boundaries, and monitoring for behavioral drift in production. This talk is intended for engineers and security practitioners building AI systems in real environments, with the goal of moving beyond output-level defenses and reasoning about securing the entire AI development pipeline.
- Bio: 12-time award-winning AI lead and "Sculpting Data For ML" author Jigyasa Grover drives rider personalization innovation at Uber after transforming Twitter/X, Facebook/Meta, Faire, and Bordo AI with large-scale ML systems. Handpicked by Google for their I/O 2024 keynote, she serves on Google's Developer Advisory Board while advising social search engine Diem and other Silicon Valley startups. As a LinkedIn Learning instructor, Jigyasa educates thousands of professionals worldwide on cutting-edge AI-powered applications and agentic AI systems. As a Google Developer Expert, Women Techmaker Ambassador, and World Economic Forum Global Shaper, she has been featured in Forbes, Business Insider, VentureBeat, and International Business Times, and has elevated panels with Harvard University, Preston-Werner Ventures, Norwegian Business School, Humanitarian Frontier in AI, Women in Data, and more. The UC San Diego alumna has secured funding from the Canadian and Norwegian governments, the Linux Foundation, and multiple tech giants, enabling work that transcends geographical boundaries. With 200+ media features and contributions to open source recognized by Apache and Python Software Foundations, she mentors next-generation talent while shaping AI's future through advisory roles at Bezoku AI, Las Positas College, and various AI forums.

### Talk 2 - Breaking Pacemaker Authentication with Formal Methods

- Topic: Attacks on Radio Protocols (SDR), Network Protocols, Analysis, and Attacks, Attacks on Cryptographic Schemes and Defense Strategies, Safety-critical system
- Speaker: [Christian Coduri](https://www.linkedin.com/in/christiancoduri/)
- Abstract: Implantable medical devices such as pacemakers are wireless, networked computers embedded in the human body. Like any connected system, they rely on authentication and access control protocols to determine who can communicate with them and under what conditions. This talk begins with an overview of the main security architectures proposed in the medical device literature, including proximity-based schemes, biometric authentication, proxy-based guardians, and hybrid designs. We examine how they work, their security guarantees, and the assumptions on which they depend. From there, we shift to a security engineer's perspective. What happens when we stop trusting the design and formally verify it? Using ProVerif, we demonstrate how security protocols can be modeled, how adversarial capabilities are defined, and how formal verification tools can uncover attack paths beyond human intuition. Finally, we present the formal analysis of a widely known implantable device protocol. Our verification reveals a subtle authentication flaw that enables session key forgery and device impersonation without breaking any cryptographic primitive. The math holds. The logic doesn't.
- Bio: I earned my Bachelor's degree in Security of Systems and Computer Networks from the University of Milan in 2023, graduating with honors. I then moved to Turin, where in 2025 I became one of the first graduates of the M.Sc. program in Cybersecurity Engineering at the Politecnico di Torino, again graduating with honors. I am currently pursuing a Ph.D. in Computer Engineering at the DAUIN Department of the same university. My research focuses on medical data management, cybersecurity for medical systems, and AI security.

### Talk 3 - One Ring 0 to Rule Them All: pwn the Windows Kernel by patching it

- Topic: Mobile and OS Security
- Speaker: Rosario Matteo Grammatico
- Abstract: A legitimately signed driver with an IOCTL interface that exposes MmMapIoSpace with no input validation. We will explore how this single oversight leads to a dangerous arbitrary kernel read/write primitive and what becomes possible when that kind of power falls into the wrong hands. We will patch the Windows Kernel for fun and discover what we are truly capable of once we reach Ring 0.
- Bio: I am a Cyber Security Analyst at Iliad Italia and a security researcher for fun. I'm focused on low-level security and adversarial techniques, exploring malware analysis, reverse engineering, vulnerability research, EDR evasion, and kernel exploitation. Driven by curiosity to understand how things break and how to build stronger defenses.

### Talk 4 - AI and the Death of Privacy? Navigating New Threats and Modern Defenses

- Topic: Privacy and Anonymity
- Speaker: [Tao Wang](https://www.linkedin.com/in/tao-wang-2b49433a7/)
- Abstract: In 2026, AI has evolved into a "privacy accelerant" that both amplifies old vulnerabilities and creates entirely new categories of risk. This session breaks down the AI privacy crisis into two core dimensions: Systemic Endogenous Risks, where AI's massive data hunger and "model memory" allow for exploits like membership inference and data reconstruction, and Functional Misuse, where AI's "superpowers" enable the inference of sensitive personal traits from benign metadata and the generation of high-fidelity deepfakes. To address these challenges, we evaluate the modern defensive toolkit, contrasting formal methods like differential privacy, which provides mathematical guarantees, with heuristic tactics such as adversarial perturbations and synthetic data. By the end of this talk, participants will have a strategic roadmap for navigating the "Privacy Paradox" and implementing resilient, privacy-preserving AI frameworks in an increasingly automated world.
- Bio: Dr. Wang is a dedicated researcher specializing in AI privacy, multimedia privacy, and the security of generative AI. He has published over 20 papers in prestigious international journals and conferences, including IEEE TPAMI, TIFS, TDSC, ACM Multimedia, and CSUR. His research on "Privacy in AIGC" has been recognized as an ESI Highly Cited Paper. Beyond his research, Dr. Wang actively contributes to the scientific community as a reviewer for top-tier venues such as ICLR, KDD, TDSC, TOMM, TBIOM, and TKDE. He is a recipient of the Chinese National Scholarship and received an Honourable Mention Award at the ACM International Multimedia Conference. His work is supported by the CAST Young Sci-Tech Talent Cultivation Project. He is an active member of the ACM EIGTRUST and China CSIG.

### Talk 5 - AI governance: Deep dive of the security of LLM

- Topic: AI Security and Attacks on AI Systems
- Speaker: [Raoul Alfredo Rocher](https://www.linkedin.com/in/raoulalfredorocher/)
- Abstract: The idea is to explore what is Agentic AI, what IBM intend for Agentic AI governance with a deep dive in the most important attack in LLM e agentic ai and how to protect.
+ 1 Agentic AI
+ 2 Agentic AI governance: monitoring, guardrailing and security
+ 3 Agentic AI and LLM main attack
+ 4 How to protect from attacker in LLM
- Bio: I am a professional with a strong inclination towards innovation, continuous learning, and research. I am passionate about technological challenges and innovations, always seeking advanced solutions in the fields of artificial intelligence and cybersecurity. I have substantial hands-on experience in Network, Security, data science, both as a Technical Sales and Data Scientist, and I am committed to leading and contributing to the creation of Gen AI and Agent-based solutions with my new roles as AI Leader in Italy for IBM Italy.


### Talk 6 - Make the analysis fun again!

- Topic: Malware Analysis and Detection
- Speaker: [Gianluigi Imbelli](https://www.linkedin.com/in/gianluigi-imbelli-8a13372a6/)
- Abstract: The talk is about an indie game with the objective to destroy a malware. In practice the gamer does some static and dynamic analysis to get some sort of key to move forward in the game. If you're not able to win in a certain amount of time, the OS gets destroyed like with a wiper malware. In the game you get insight about the malware and there are augments that slow down or freeze the malware process. You can get hints for handling the malware disassemble, but when you get a hint, the malware process speeds up.
- Bio: I'm Gianluigi Imbelli and I'm from Benevento. This is my last year as a student at the University of Milan and I want to learn more about malware and malware reversing. This would be my first experience in making a useful game to make people get a joyful approach to learning malware analysis.

### Talk 7 - Everything in the Cloud looks secure... Until It isn’t

- Topic: Cloud and Hypervisor Security
- Speaker: [Matteo Balasco](https://www.linkedin.com/in/mttbal)
- Abstract: Cloud environments are rarely breached through exotic zero-days. More often, the root cause is a misconfiguration that looks fine in the architecture diagram, passes automated scans, and still leaves the door wide open.

This talk focuses not only on standard security best practices, but also on the subtle AWS misconfigurations that actually matter in production, the ones that survive audits precisely because nothing breaks and no alerts fire. We’ll explore how configurations that appear secure at every layer can still be exploited laterally, and why the gap between what your architecture looks like and what it actually does is where attackers thrive.

All examples are drawn from real production environments, because theory is rarely where the problems hide.
- Bio: I’m a Security Engineer specializing in cloud, network, and corporate security. I currently work at Docebo, where I manage threat detection and response across multi-cloud infrastructure, drive CNAPP/CSPM adoption, and work on DevSecOps automation.

I have a background as a System Engineer and Network Engineer, and I’m an AWS Certified Solutions Architect, Associate and ISC2 SSCP certified, with hands-on experience across the full incident lifecycle.

### Reach Milan0Day

Aula Magna **Bertoni** (_Floor 0_), Via Giovanni Celoria, 18, 20133 Milano MI

<center>
<img src="/images/event/mappamilan0day26.webp" width="700">
</center>

### Where to eat?

- Street food stands & trucks along Via Celoria and Via Golgi
- Bar (Physics Department), Via Celoria 16
- Bar Calicantus, Via Golgi 9

### Patronage

<img src="/images/associazioni/dipartimentoinformaticastatale.webp" width=300px>
