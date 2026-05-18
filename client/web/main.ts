import path from "path";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "child_process";
import { app, BrowserWindow } from "electron";

let proxyProcess: ChildProcessWithoutNullStreams | null = null;

const proxyPort = "9883";

const getProxyPaths = (): { command: string; args: string[]; cwd: string } => {
  if (app.isPackaged) {
    const proxyDir = path.join(process.resourcesPath, "proxy");
    return {
      command: path.join(proxyDir, "krb-client-proxy.exe"),
      args: [
        "--config",
        path.join(proxyDir, "client_config.json"),
        "--host",
        "127.0.0.1",
        "--port",
        proxyPort,
      ],
      cwd: proxyDir,
    };
  }

  const proxyDir = path.resolve(__dirname, "../../proxy");
  const pythonCommand = process.platform === "win32" ? "python" : "python3";
  return {
    command: pythonCommand,
    args: [
      path.join(proxyDir, "main.py"),
      "--config",
      path.join(proxyDir, "client_config.json"),
      "--host",
      "127.0.0.1",
      "--port",
      proxyPort,
    ],
    cwd: proxyDir,
  };
};

const startProxyProcess = (): void => {
  if (proxyProcess) {
    return;
  }

  const { command, args, cwd } = getProxyPaths();
  proxyProcess = spawn(command, args, {
    cwd,
    windowsHide: true,
  });

  proxyProcess.stdout.on("data", (data: Buffer) => {
    console.log(`[proxy] ${data.toString().trimEnd()}`);
  });

  proxyProcess.stderr.on("data", (data: Buffer) => {
    console.error(`[proxy] ${data.toString().trimEnd()}`);
  });

  proxyProcess.on("exit", (code, signal) => {
    console.log(`[proxy] exited code=${code ?? "null"} signal=${signal ?? "null"}`);
    proxyProcess = null;
  });

  proxyProcess.on("error", (error) => {
    console.error("[proxy] failed to start", error);
    proxyProcess = null;
  });
};

const stopProxyProcess = (): void => {
  if (!proxyProcess || proxyProcess.pid === undefined) {
    proxyProcess = null;
    return;
  }

  const pid = proxyProcess.pid;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
  } else {
    proxyProcess.kill("SIGTERM");
  }

  proxyProcess = null;
};

const createWindow = (): void => {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 760,
    minWidth: 900,
    minHeight: 600,
    title: "Kerberos Client",
  });

  const shouldOpenDevTools = false // true;
  mainWindow.loadFile(path.join(__dirname, "renderer/index.html"));

  if (shouldOpenDevTools) {
    mainWindow.webContents.openDevTools({ mode: "detach" });
  }
};

app.whenReady().then(() => {
  startProxyProcess();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  stopProxyProcess();
});

app.on("quit", () => {
  stopProxyProcess();
});
