declare global {
  interface Window {
    systemApi: {
      getHealth: () => Promise<{ status: string; timestamp: string }>;
    };
  }
}

export {};
