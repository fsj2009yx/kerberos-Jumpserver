import express from "express";
import cors from "cors";
import systemRouter from "./routes/system";

let started = false;

export const startApiServer = (port: number): void => {
  if (started) {
    return;
  }

  const app = express();
  app.use(cors());
  app.use(express.json());

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.use("/api/system", systemRouter);

  app.listen(port, () => {
    console.log(`[web-api] listening on http://127.0.0.1:${port}`);
  });

  started = true;
};
