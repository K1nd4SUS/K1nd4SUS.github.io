export interface Author {
    slug: string;
    name: string;
    username: string;
    role: string;
    bio?: string;
    email?: string;
    github?: string;
    link?: string;
    linkedin?: string;
    telegram?: string;
    instagram?: string;
    university?: string;
    tags?: string[];
    // avatarURL?: string;
}

export const authors: Author[] = [
{
    slug: "S-Mancl",
    name: "Samuele Manclossi",
    university: "Università degli Studi di Milano",
    role: "🜲 President & Co-Founder",
    bio: "Bio",
    username: "S-Mancl",
    linkedin: "https://www.linkedin.com/in/samuele-manclossi/",
    telegram: "https://t.me/s3m_mancl",
    tags: ["rev", "crypto", "misc"],
  },
  {
    slug: "5alv1.py",
    name: "Cristian Salvi",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & Treasurer",
    bio: "Just a pwner",
    github: "https://github.com/5alv1",
    telegram: "https://t.me/salv1ni",
    username: "5alv1.py",
    tags: ["pwn", "rev"],
  },
  {
    slug: "andre",
    name: "Andrea Lunghi",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & CTF",
    bio: "Cybersecurity@UniMi, Pentester & CTF player",
    username: "andre",
    linkedin: "https://www.linkedin.com/in/andrea-lunghi/",
    link: "https://andrealungh1.github.io/",
    email: "https://mail.google.com/mail/u/0/?fs=1&tf=cm&source=mailto&to=andrea.lunghi@studenti.unimi.it",
    tags: ["web", "misc"],
},
  {
    slug: "niccolovlnt",
    name: "Niccolò Volontè",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & Social-media",
    bio: "Cloud security enthusiast & CTF player",
    username: "niccolovlnt",
    linkedin: "https://www.linkedin.com/in/niccol%C3%B3-volont%C3%A8-a03108252/",
    telegram: "https://t.me/niccolovlnt",
    link: "https://me.nicklab.it/",
    github: "https://github.com/niccolovlnt",
    email: "volonte.niccolo@gmail.com",
    tags: ["web", "misc", "network"],
  },
  {
    slug: "melloc",
    name: "Alessandro Mellone",
    role: "Vicepresident & Events",
    university: "Università degli Studi di Milano",
    bio: "Cybersec@UniMi, CTF player",
    username: "melloc",
    linkedin: "https://www.linkedin.com/in/alessandro-mellone-2983951bb/",
    instagram: "https://www.instagram.com/ale.mellone/",
    telegram: "https://t.me/melloc03",
    tags: ["misc", "network"],
  },
  {
    slug: "Privitorta",
    name: "Emma Privitera",
    role: "Admin & Webdev",
    university: "Università degli Studi di Milano",
    bio: "Cybersec@UniMi, CTF player, Web developer & all-around tech enthusiast",
    username: "Privitorta",
    github: "https://github.com/privitorta",
    linkedin: "https://www.linkedin.com/in/emmaprivitera/",
    telegram: "https://t.me/t3staocr0ce",
    instagram: "https://www.instagram.com/privitorta/",
    email: "emma.privitera.505@gmail.com",
    tags: ["web", "osint"],
  },
  {
    slug: "perfumo",
    name: "Mattia Perfumo",
    role: "EX President & Co-Founder",
    bio: "Cybersecurity@KTH, cybersec enthusiast & CTF player",
    university: "Kungliga Tekniska Högskolan",
    username: "perfumo",
    link: "https://mattiaperfumo.it/",
    github: "https://github.com/mperf",
    linkedin: "https://www.linkedin.com/in/mattia-perfumo-08201013a/",
    email: "mperf21@proton.me",
    telegram: "https://t.me/Perf21",
    tags: ["web", "osint", "network"],
  },
  {
  slug: "RebelNightmare_",
  name: "Melissa Moioli",
  bio: "Cybersecurity student, passionate about reverse engineering, software security and forensic analysis",
  role: "Member",
  university: "Politecnico di Torino",
  tags: ["rev", "forensics", "binary"],
  github: "https://github.com/Rebel-Nightmare",
  linkedin: "https://www.linkedin.com/in/melissa-m-839739254",
  username: "RebelNightmare_",
  },
  {
  slug: "Tiz314",
  name: "Tiziano Radicchi",
  bio: "Cybersec@PoliTO - Reverse engineering & Computer forensics",
  role: "EX Vicepresident & Co-Founder",
  university: "Politecnico di Torino",
  tags: ["rev", "forensics"],
  username: "Tiz314",
  link: "https://tiz314.it/",
  github: "https://github.com/tiz314",
  },
  {
    slug: "IvAlexEv",
    name: "Aleksandar Ivanov",
    role: "Member",
    bio: "Passionate about all things cybersecurity, with a focus on penetration testing and red teaming. CTF and HTB player",
    university: "Penetration Tester @ Capgemini",
    tags: ["web", "misc", "pwn"],
    username: "IvAlexEv",
    link: "https://ivalexev.gitbook.io/rednote",
    linkedin: "https://www.linkedin.com/in/IvAlexEv",
    github: "https://github.com/IvAlexEv",
  },
];