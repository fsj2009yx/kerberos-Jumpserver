import { useEffect, useMemo, useRef, useState } from "react";
import { animate, stagger } from "motion";
import Login from "./component/login";
import Logs from "./component/logs";
import Terminal from "./component/terminal";
import { getState, login, logout, sendLogoutBeacon } from "./utils/api_calls";

type ViewKey = "terminal" | "logs";

type ViewState = {
  title: string;
  body?: string;
};

const viewContent: Record<ViewKey, ViewState> = {
  terminal: {
    title: "Terminal",
  },
  logs: {
    title: "Logs",
    body: "See the logs and the data.",
  },
};

const App = (): JSX.Element => {
  const [activeView, setActiveView] = useState<ViewKey>("logs");
  const [message, setMessage] = useState<string | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false); // useState(false);
  const headerRef = useRef<HTMLDivElement | null>(null);

  const content = useMemo(() => viewContent[activeView], [activeView]);
  const showTerminal = activeView === "terminal";
  const isLoginScreen = !isAuthenticated;

  useEffect(() => {
    if (!isAuthenticated) {
      return undefined;
    }

    const handlePageExit = (): void => {
      sendLogoutBeacon();
    };

    window.addEventListener("beforeunload", handlePageExit);
    window.addEventListener("pagehide", handlePageExit);

    return () => {
      window.removeEventListener("beforeunload", handlePageExit);
      window.removeEventListener("pagehide", handlePageExit);
    };
  }, [isAuthenticated]);

  useEffect(() => {
    if (!headerRef.current) {
      return undefined;
    }

    const tabs = Array.from(
      headerRef.current.querySelectorAll<HTMLElement>(".app-tab"),
    );
    const controls = [] as Array<{ cancel: () => void }>;

    if (tabs.length) {
      controls.push(
        animate(
          tabs,
          { opacity: [0, 1], y: [10, 0] },
          { delay: stagger(0.05), duration: 0.35, easing: "ease-out" },
        ),
      );
    }

    return () => {
      controls.forEach((control) => control.cancel());
    };
  }, [activeView]);

  const handleLogin = async (
    username: string,
    password: string,
  ): Promise<void> => {
    setLoginError(null);

    try {
      await login(username, password);

      setIsAuthenticated(true);
      setActiveView("logs");
    } catch (error) {
      const text = error instanceof Error ? error.message : "Login failed.";
      setLoginError(text);
    }
  };

  const handleStateCheck = async (): Promise<void> => {
    setMessage(null);
    try {
      const data = await getState();
      setMessage(
        `State: ${data.state} | Seq: ${data.seq_num} | TGT: ${data.tgt_expire} | TV: ${data.tv_expire}`,
      );
    } catch (error) {
      const text = error instanceof Error ? error.message : "Unknown error";
      setMessage(`API call failed: ${text}`);
    }
  };

  const handleLogout = async (): Promise<void> => {
    try {
      await logout();
    } catch (error) {
      const text = error instanceof Error ? error.message : "Logout failed.";
      setMessage(text);
    }
    setIsAuthenticated(false);
    setLoginError(null);
    setActiveView("logs");
  };

  if (isLoginScreen) {
    return <Login error={loginError} onLogin={handleLogin} />;
  }

  return (
    <div className="layout">
      <main className="main-panel">
        <header className="app-header" ref={headerRef}>
          <div className="app-header-top">
            <div>
              <p className="app-eyebrow">Kerberos Client</p>
              <h1 className="app-title">{content.title}</h1>
            </div>
            <div className="app-actions">
              <div className="api-status">
                {message ? <span className="health-status">{message}</span> : null}
                <button
                  className="action-button"
                  type="button"
                  onClick={handleStateCheck}
                >
                  Check API State
                </button>
              </div>
              <button className="action-button" type="button" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </div>
          <div
            className="app-header-bottom"
            role="tablist"
            aria-label="Views"
          >
            {(Object.keys(viewContent) as ViewKey[]).map((view) => (
              <button
                key={view}
                className={`app-tab${activeView === view ? " is-active" : ""}`}
                type="button"
                role="tab"
                aria-selected={activeView === view}
                onClick={() => setActiveView(view)}
              >
                {viewContent[view].title}
              </button>
            ))}
          </div>
        </header>

        <section className="content-card">
          {activeView === "logs" ? <Logs /> : null}
          <div className={`terminal-panel${showTerminal ? " is-active" : ""}`}>
            <Terminal isVisible={showTerminal} isAuthenticated={isAuthenticated} />
          </div>
        </section>
      </main>
    </div>
  );
};

export default App;
