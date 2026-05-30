import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const writeups = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/writeups" }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    platform: z.string(),
    tags: z.array(z.string()).optional().default([]),
    difficulty: z
      .enum(["easy", "medium", "hard", "n/a"])
      .optional()
      .default("n/a"),
    tools: z.array(z.string()).optional(),
  }),
});

export const collections = { writeups };
