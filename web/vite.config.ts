import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// GitHub Pages serves the site under /pq-permit/; set BASE=/ for other hosts.
export default defineConfig({
  plugins: [react()],
  base: process.env.BASE ?? "/pq-permit/",
});
