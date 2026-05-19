import path from "path";
import fs from "fs";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "child_process";
import { app, BrowserWindow } from "electron";

let proxyProcess: ChildProcessWithoutNullStreams | null = null;

const proxyPort = "9883";

const getAppRoot = (): string => {
  if (app.isPackaged) {
    return path.dirname(process.execPath);
  }
  return path.resolve(__dirname, "..");
};

const ensureLogsDir = (): string => {
  const logsDir = path.join(getAppRoot(), "logs");
  fs.mkdirSync(logsDir, { recursive: true });
  return logsDir;
};

const appendLog = (fileName: string, message: string): void => {
  try {
    const logsDir = ensureLogsDir();
    const line = `[${new Date().toISOString()}] ${message}\n`;
    fs.appendFileSync(path.join(logsDir, fileName), line, "utf-8");
  } catch {
    // Keep the app running even if the install directory is not writable.
  }
};

const logMain = (message: string): void => {
  console.log(message);
  appendLog("electron-main.log", message);
};

const logMainError = (message: string, error?: unknown): void => {
  const detail = error instanceof Error ? `${message}: ${error.stack ?? error.message}` : message;
  console.error(detail);
  appendLog("electron-main.log", detail);
};

const logProxy = (message: string): void => {
  console.log(message);
  appendLog("proxy-process.log", message);
};

const getConfigRoot = (): string => {
  return path.join(getAppRoot(), "config");
};

const assertPathExists = (targetPath: string, label: string): void => {
  if (!fs.existsSync(targetPath)) {
    throw new Error(`Packaged ${label} is missing: ${targetPath}`);
  }
};

const preparePackagedProxyRuntime = (): { command: string; args: string[]; cwd: string } => {
  const resourceProxyDir = path.join(process.resourcesPath, "proxy");
  const configRoot = getConfigRoot();
  const configProxyDir = path.join(configRoot, "proxy");
  const runtimeConfigPath = path.join(configProxyDir, "client_config.json");

  assertPathExists(path.join(resourceProxyDir, "krb-client-proxy.exe"), "proxy executable");
  assertPathExists(runtimeConfigPath, "client config");
  assertPathExists(path.join(configRoot, "certs", "cert_client.json"), "client certificate");
  assertPathExists(path.join(configRoot, "certs", "v_cert.json"), "V certificate");
  assertPathExists(path.join(configRoot, "keys", "client_priv.json"), "client private key");

  return {
    command: path.join(resourceProxyDir, "krb-client-proxy.exe"),
    args: [
      "--config",
      runtimeConfigPath,
      "--host",
      "127.0.0.1",
      "--port",
      proxyPort,
    ],
    cwd: configProxyDir,
  };
};

const getProxyPaths = (): { command: string; args: string[]; cwd: string } => {
  if (app.isPackaged) {
    return preparePackagedProxyRuntime();
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
  const logsDir = ensureLogsDir();
  logMain(`logs dir: ${logsDir}`);
  logMain(`starting proxy command=${command} cwd=${cwd}`);

  proxyProcess = spawn(command, args, {
    cwd,
    env: {
      ...process.env,
      KRB_CLIENT_LOG_DIR: logsDir,
    },
    windowsHide: true,
  });

  proxyProcess.stdout.on("data", (data: Buffer) => {
    logProxy(`[proxy:stdout] ${data.toString().trimEnd()}`);
  });

  proxyProcess.stderr.on("data", (data: Buffer) => {
    logProxy(`[proxy:stderr] ${data.toString().trimEnd()}`);
  });

  proxyProcess.on("exit", (code, signal) => {
    logProxy(`[proxy] exited code=${code ?? "null"} signal=${signal ?? "null"}`);
    proxyProcess = null;
  });

  proxyProcess.on("error", (error) => {
    logMainError("[proxy] failed to start", error);
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
