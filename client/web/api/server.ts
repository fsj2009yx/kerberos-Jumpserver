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

  app.post("/api/login", (req, res) => {
    const { username, password } = req.body as {
      username?: string;
      password?: string;
    };

    if (!username || !password) {
      res.status(400).json({ ok: false, message: "Username and password required." });
      return;
    }

    res.json({ ok: true, user: { username } });
  });

  app.use("/api/system", systemRouter);

  app.listen(port, () => {
    console.log(`[web-api] listening on http://127.0.0.1:${port}`);
  });

  started = true;
};
