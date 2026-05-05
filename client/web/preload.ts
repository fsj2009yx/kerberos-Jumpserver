import { contextBridge } from "electron";

const BASE_URL = "http://127.0.0.1:3001";

contextBridge.exposeInMainWorld("systemApi", {
  login: async (
    username: string,
    password: string
  ): Promise<{ ok: boolean; user?: { username: string }; message?: string }> => {
    const response = await fetch(`${BASE_URL}/api/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ username, password })
    });

    const payload = (await response.json()) as {
      ok: boolean;
      user?: { username: string };
      message?: string;
    };

    if (!response.ok || !payload.ok) {
      const message = payload.message ?? `Login failed with status ${response.status}`;
      throw new Error(message);
    }

    return payload;
  },
  getHealth: async (): Promise<{ status: string; timestamp: string }> => {
    const response = await fetch(`${BASE_URL}/api/system/health`);
    if (!response.ok) {
      throw new Error(`Health API failed with status ${response.status}`);
    }

    return response.json() as Promise<{ status: string; timestamp: string }>;
  }
});
