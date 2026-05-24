import { defineCollection, z } from "astro:content";

const writeups = defineCollection({
  type: "content",
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
