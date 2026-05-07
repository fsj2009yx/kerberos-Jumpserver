import path from "path";
import { app, BrowserWindow } from "electron";

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
});
