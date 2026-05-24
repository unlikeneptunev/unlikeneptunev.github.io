import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const writeups = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/writeups" }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()),
    difficulty: z.enum(["easy", "medium", "hard"]),
    tools: z.array(z.string()).optional(),
  }),
});

export const collections = { writeups };
