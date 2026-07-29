import "dotenv/config";
import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import cors from "cors";
import { initDb } from "./database.ts";
import { wafMiddleware } from "./waf.ts";
import { apiRouter } from "./routes.ts";

async function startServer() {
  const app = express();
  app.set("trust proxy", true);
  const PORT = 3000;

  // Initialize Database
  initDb();

  // Basic Middleware
  app.use(cors());
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ limit: "10mb", extended: true }));

  // API Routes (Before WAF if they are internal, but usually WAF protects everything)
  // We'll put API routes under /api and exclude them from some WAF strictness if needed, 
  // but for this demo, the WAF protects ALL routes.
  app.use(wafMiddleware);
  
  app.use("/api", apiRouter);

  // 404 handler for API
  app.use("/api", (req, res) => {
    res.status(404).json({ error: "API Route Not Found" });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 IntelliGuard WAF running at http://localhost:${PORT}`);
  });
}

startServer();
