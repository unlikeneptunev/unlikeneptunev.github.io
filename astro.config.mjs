import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";
import { unified } from "@astrojs/markdown-remark";
import remarkCodeTitle from "remark-code-title";

export default defineConfig({
  site: "https://unlikeneptunev.github.io",
  integrations: [mdx(), sitemap()],
  markdown: {
    processor: unified({
      remarkPlugins: [remarkCodeTitle],
    }),
    shikiConfig: {
      theme: "github-dark",
      wrap: true,
    },
  },
});