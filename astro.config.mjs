import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://unlikeneptunev.github.io",
  integrations: [mdx(), sitemap()],
  markdown: {
    shikiConfig: {
      theme: "github-dark",
      wrap: true,
    },
  },
  vite: {
    optimizeDeps: {
      exclude: ["pagefind"],
    },
    build: {
      rollupOptions: {
        external: ["/pagefind/pagefind.js"],
      },
    },
    plugins: [
      {
        name: "pagefind-dev-stub",
        resolveId(id) {
          if (id === "/pagefind/pagefind.js") return id;
        },
        load(id) {
          if (id === "/pagefind/pagefind.js")
            return "export default {}; export const init = () => {}; export const search = () => ({ results: [] });";
        },
      },
    ],
  },
});
