import { contextBridge } from "electron";

const BASE_URL = "http://127.0.0.1:3001";

contextBridge.exposeInMainWorld("systemApi", {
  getHealth: async (): Promise<{ status: string; timestamp: string }> => {
    const response = await fetch(`${BASE_URL}/api/system/health`);
    if (!response.ok) {
      throw new Error(`Health API failed with status ${response.status}`);
    }

    return response.json() as Promise<{ status: string; timestamp: string }>;
  }
});
