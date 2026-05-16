type LoginResult = {
  state?: string;
  error?: string;
  tgt_expire?: number;
  tv_expire?: number;
};

type StateResult = {
  state?: string;
  error?: string;
  k_ctgs_sha256?: string;
  k_cv_sha256?: string;
  tgt_expire?: number;
  tv_expire?: number;
  seq_num?: number;
};

const API_BASE_URL = "http://127.0.0.1:9883";

export const getLogsUrl = (): string => `${API_BASE_URL}/api/logs`;

export const logout = async (): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/api/logout`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`Logout failed with status ${response.status}`);
  }
};

export const sendLogoutBeacon = (): void => {
  const url = `${API_BASE_URL}/api/logout`;
  if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
    const body = new Blob([], { type: "text/plain" });
    navigator.sendBeacon(url, body);
    return;
  }
  void fetch(url, {
    method: "POST",
    keepalive: true,
  }).catch(() => undefined);
};

export const login = async (username: string, password: string): Promise<LoginResult> => {
  if (password.length > 0 && password.length !== 8) {
    throw new Error("Password has to be empty or length of 8")
  }
  const form = new URLSearchParams({
    username,
    password
  });
  const response = await fetch(`${API_BASE_URL}/api/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: form.toString()
  });

  const data = (await response.json()) as LoginResult;
  if (!response.ok || data.error) {
    throw new Error(data.error ?? `Login failed with status ${response.status}`);
  }

  return data;
};

export const getState = async (): Promise<StateResult> => {
  const response = await fetch(`${API_BASE_URL}/api/state`);
  const data = (await response.json()) as StateResult;
  if (!response.ok || data.error) {
    throw new Error(data.error ?? `State check failed with status ${response.status}`);
  }

  return data;
};
