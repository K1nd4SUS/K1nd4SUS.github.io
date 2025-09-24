export interface TeamMember {
  name: string;
  university: string;
  role: string;
  tags: string[];
  username?: string;
  github?: string;
  telegram?: string;
  linkedin?: string;
  instagram?: string;
  email?: string;
  link?: string;
}

export const teamMembers: TeamMember[] = [
  {
    name: "Samuele Manclossi",
    university: "Università degli Studi di Milano",
    role: "🜲 President & Co-Founder",
    tags: ["rev", "crypto", "misc"],
    username: "S-Mancl",
    linkedin: "https://www.linkedin.com/in/samuele-manclossi/",
    telegram: "https://t.me/s3m_mancl",
  },
  {
    name: "Cristian Salvi",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & Treasurer",
    tags: ["pwn", "rev"],
    github: "https://github.com/5alv1",
    telegram: "https://t.me/salv1ni",
    username: "5alv1.py",
  },
  {
    name: "Andrea Lunghi",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & CTF",
    tags: ["web", "misc"],
    username: "andre",
    linkedin: "https://www.linkedin.com/in/andrea-lunghi/",
    link: "https://andrealungh1.github.io/",
    email: "https://mail.google.com/mail/u/0/?fs=1&tf=cm&source=mailto&to=andrea.lunghi@studenti.unimi.it",
  },
  {
    name: "Niccolò Volontè",
    university: "Università degli Studi di Milano",
    role: "Vicepresident & Social-media",
    tags: ["web", "misc", "network"],
    username: "niccolovlnt",
    linkedin: "https://www.linkedin.com/in/niccol%C3%B3-volont%C3%A8-a03108252/",
    telegram: "https://t.me/niccolovlnt",
    link: "https://me.nicklab.it/",
    github: "https://github.com/niccolovlnt",
    email: "volonte.niccolo@gmail.com",
  },
  {
    name: "Alessandro Mellone",
    role: "Vicepresident & Events",
    university: "Università degli Studi di Milano",
    tags: ["misc", "network"],
    username: "melloc",
    linkedin: "https://www.linkedin.com/in/alessandro-mellone-2983951bb/",
    instagram: "https://www.instagram.com/ale.mellone/",
    telegram: "https://t.me/melloc03",
  },
  {
    name: "Emma Privitera",
    role: "Admin & Webdev",
    university: "Università degli Studi di Milano",
    tags: ["web", "osint"],
    username: "Privitorta",
    github: "https://github.com/privitorta",
    linkedin: "https://www.linkedin.com/in/emmaprivitera/",
    telegram: "https://t.me/t3staocr0ce",
    instagram: "https://www.instagram.com/privitorta/",
    email: "emma.privitera.505@gmail.com",
  },
  {
    name: "Mattia Perfumo",
    role: "EX President & Co-Founder",
    university: "Kungliga Tekniska Högskolan",
    tags: ["web", "osint", "network"],
    username: "perfumo",
    link: "https://mattiaperfumo.it/",
    github: "https://github.com/mperf",
    linkedin: "https://www.linkedin.com/in/mattia-perfumo-08201013a/",
    email: "mperf21@proton.me",
    telegram: "https://t.me/Perf21"
  },
  {
    name: "Tiziano Radicchi",
    role: "EX Vicepresident & Co-Founder",
    university: "Politecnico di Torino",
    tags: ["rev", "forensics"],
    username: "Tiz314",
    link: "https://tiz314.it/",
    github: "https://github.com/tiz314",
  },
  {
    name: "Matteo Zoia",
    role: "EX Vicepresident & Co-Founder",
    university: ". . .",
    tags: ["pwn"],
    username: "teozoia",
  },
  {
    name: "Mirco Picca",
    role: "EX Vicepresident",
    university: "Università degli Studi di Milano",
    tags: ["pwn", "web", "rev"],
    username: "Kribas",
    github: "https://github.com/Kr1bas",
    linkedin: "https://www.linkedin.com/in/mirco-picca-577647211",
  },
  {
    name: "Marco Galvagni",
    role: "Co-Founder",
    university: "Security Engineer @ CybergON",
    tags: ["web", "crypto"],
    username: "M4RC02U1F4A4",
    linkedin: "https://www.linkedin.com/in/marco-galvagni/",
    github: "https://github.com/M4RC02U1F4A4"
  },
  {
    name: "Edoardo della Rossa",
    role: "Co-Founder",
    university: "PhD Student @ TU/e",
    tags: ["rev", "binary", "hardware"],
    username: "Miniman",
    telegram: "https://t.me/Miniman",
    linkedin: "https://www.linkedin.com/in/edoardo-della-rossa-888748254/",
  },
  {
    name: "Alberto Ovena",
    role: "Member",
    university: "Politecnico di Torino",
    tags: ["crypto"],
    username: "mightygibbon",
    github: "https://github.com/mightygibbon",
    linkedin: "https://www.linkedin.com/in/alberto-ovena/",
  },
  {
    name: "Melissa Moioli",
    role: "Member",
    university: "Politecnico di Torino",
    tags: ["rev", "forensics", "binary"],
    github: "https://github.com/Rebel-Nightmare",
    linkedin: "https://www.linkedin.com/in/melissa-m-839739254",
    username: "RebelNightmare_",
  },
  {
    name: "Aleksandar Ivanov",
    role: "Member",
    university: "Penetration Tester @ Capgemini",
    tags: ["misc", "osint"],
    username: "IvAlexEv",
    link: "https://ivalexev.gitbook.io/rednote",
    linkedin: "https://www.linkedin.com/in/IvAlexEv",
    github: "https://github.com/IvAlexEv",
  },
  {
    name: "Edoardo (Veprion)",
    role: "Member",
    university: ". . .",
    tags: ["crypto", "misc", "osint"],
    username: "Veprion",
    telegram: "https://t.me/Veprion",
  },
  {
    name: "Andrea Sacchi",
    role: "Member",
    university: "Università degli Studi di Milano",
    tags: ["web", "rev"],
    username: "alsacchi",
    link: "https://www.0x41414141.it/",
    github: "https://github.com/alsacchi",
    telegram: "https://t.me/alsacchi",
    linkedin: "https://www.linkedin.com/in/andrea-0x41414141/",
  },
  {
    name: "Pietro Lepori",
    role: "Member",
    university: ". . .",
    tags: ["crypto"],
    username: "Pi",
    linkedin: "https://www.linkedin.com/in/pietro-lepori/",
  },
  {
    name: "Rocco Amico",
    role: "Member",
    university: "Università degli Studi di Milano",
    tags: ["misc", "osint"],
    username: "[kuom]",
    github: "https://github.com/ohkuom"
  },
  {
    name: "Vincenzo",
    role: "Member",
    university: ". . .",
    tags: ["web", "misc"],
    username: "Sniirful",
    github: "https://github.com/sniirful",
  }
];
