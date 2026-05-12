import { defineConfig } from 'astro/config';
import tailwindcss from "@tailwindcss/vite";
import preact from "@astrojs/preact";
import sitemap from "@astrojs/sitemap";
import icon from "astro-icon";
import node from "@astrojs/node";

export default defineConfig({
  site: "https://supersecretdemo.nicklab.it",
  adapter: node({
    mode: "standalone",
  }),
  integrations: [
    preact(),
    icon(),
    sitemap({
      filter: (page) =>
        !page.includes("/blog/tags") &&
        !page.includes("/blog/techs"),
    }),
  ],

  server: {
    host: '0.0.0.0',
    port: 4321,
  },

  vite: {
    plugins: [tailwindcss()],
  },

  markdown: {
    shikiConfig: {
      theme: 'github-dark',
    },
  },
});