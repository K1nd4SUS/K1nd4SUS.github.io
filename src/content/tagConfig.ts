export interface TagConfig {
  name: string;
  icon: string; // nome file svg in src/icons
  bg: string; // classe tailwind per bg
  text: string; // classe tailwind per testo
}

export const tagConfig: Record<string, TagConfig> = {
  
  pwn: { 
    name: 'pwn', 
    icon: 'pwn', 
    bg: 'bg-[#880015]', // rosso scuro
    text: 'text-white' 
}, // blu scuro

  crypto: { 
    name: 'crypto', 
    icon: 'crypto', 
    bg: 'bg-[#2A5E26]', // verde
    text: 'text-white' 
},

  web: { 
    name: 'web', 
    icon: 'web', 
    bg: 'bg-[#191D52]', // blu scuro
    text: 'text-white' 
  },

  forensics: { 
    name: 'forensics', 
    icon: 'forensics', 
    bg: 'bg-[#7092BE]', // indaco chiaro
    text: 'text-white' 
  },

  network: { 
    name: 'network', 
    icon: 'network', 
    bg: 'bg-[#51549E]', // lilla
    text: 'text-white' 
  },

  misc: { 
    name: 'misc', 
    icon: 'misc', 
    bg: 'bg-[#8C6F08]', // giallo ocra
    text: 'text-white' 
  },

  rev: { 
    name: 'rev', 
    icon: 'rev', 
    bg: 'bg-[#96571A]', // marrone aranciato
    text: 'text-white' 
},

  binary: { 
    name: 'binary', 
    icon: 'binary', 
    bg: 'bg-[#176378]', // blu
    text: 'text-white' 
},

  osint: { 
    name: 'osint', 
    icon: 'osint', 
    bg: 'bg-[#8C275F]', // fucsia
    text: 'text-white' 
  },

  hardware: { 
    name: 'hardware', 
    icon: 'hardware', 
    bg: 'bg-[#6A0DAD]', // viola
    text: 'text-white' 
  }
};
