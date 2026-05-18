import path from "path";
import fs from "fs";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "child_process";
import { app, BrowserWindow } from "electron";

let proxyProcess: ChildProcessWithoutNullStreams | null = null;

const proxyPort = "9883";

const copyDefaultResource = (from: string, to: string): void => {
  if (fs.existsSync(to)) {
    return;
  }

  if (!fs.existsSync(from)) {
    throw new Error(`Packaged resource is missing: ${from}`);
  }

  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.cpSync(from, to, { recursive: true });
};

const writeRuntimeConfig = (configPath: string, runtimeRoot: string, runtimeProxyDir: string): void => {
  const config = JSON.parse(fs.readFileSync(configPath, "utf-8")) as Record<string, unknown>;
  const runtimeConfig = {
    ...config,
    cert_path: path.join(runtimeRoot, "certs", "cert_client.json"),
    privkey_path: path.join(runtimeRoot, "keys", "client_priv.json"),
    v_cert_path: path.join(runtimeRoot, "certs", "v_cert.json"),
    ticket_store_path: path.join(runtimeProxyDir, "tickets", "ticket.bin"),
  };

  fs.writeFileSync(configPath, `${JSON.stringify(runtimeConfig, null, 4)}\n`, "utf-8");
};

const preparePackagedProxyRuntime = (): { command: string; args: string[]; cwd: string } => {
  const resourceProxyDir = path.join(process.resourcesPath, "proxy");
  const runtimeRoot = app.getPath("userData");
  const runtimeProxyDir = path.join(runtimeRoot, "proxy");
  const runtimeConfigPath = path.join(runtimeProxyDir, "client_config.json");

  copyDefaultResource(
    path.join(resourceProxyDir, "client_config.json"),
    runtimeConfigPath,
  );
  copyDefaultResource(
    path.join(process.resourcesPath, "certs", "cert_client.json"),
    path.join(runtimeRoot, "certs", "cert_client.json"),
  );
  copyDefaultResource(
    path.join(process.resourcesPath, "certs", "v_cert.json"),
    path.join(runtimeRoot, "certs", "v_cert.json"),
  );
  copyDefaultResource(
    path.join(process.resourcesPath, "keys", "client_priv.json"),
    path.join(runtimeRoot, "keys", "client_priv.json"),
  );
  writeRuntimeConfig(runtimeConfigPath, runtimeRoot, runtimeProxyDir);

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
    cwd: runtimeProxyDir,
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
