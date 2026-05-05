declare global {
  interface Window {
    systemApi: {
      login: (
        username: string,
        password: string
      ) => Promise<{ ok: boolean; user?: { username: string }; message?: string }>;
      getHealth: () => Promise<{ status: string; timestamp: string }>;
    };
  }
}

export {};
