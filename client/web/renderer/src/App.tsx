import { useMemo, useState } from "react";
import Login from "./component/login";
import Logs from "./component/logs";
import Terminal from "./component/terminal";
import { getState, login } from "./utils/api_calls";

type ViewKey = "login" | "terminal" | "logs";

type ViewState = {
  title: string;
  body?: string;
};

const viewContent: Record<ViewKey, ViewState> = {
  login: {
    title: "Login",
    body: "Welcome. This is the login view.",
  },
  terminal: {
    title: "Terminal",
  },
  logs: {
    title: "Logs",
    body: "See the logs and the data.",
  },
};

const App = (): JSX.Element => {
  const [activeView, setActiveView] = useState<ViewKey>("login");
  const [message, setMessage] = useState<string | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false); // useState(false);

  const content = useMemo(() => viewContent[activeView], [activeView]);
  const loginLabel = isAuthenticated ? "Logout" : "Login";
  const showTerminal = activeView === "terminal";

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

  const handleLogout = (): void => {
    setIsAuthenticated(false);
    setMessage(null);
    setLoginError(null);
    setActiveView("login");
  };

  return (
    <div className="layout">
      <aside className="menu-panel">
        <div className="menu-title">Kerberos Client</div>
        <nav className="menu-list" aria-label="Main menu">
          {Object.keys(viewContent).map((key) => {
            const view = key as ViewKey;
            const isLocked = !isAuthenticated && view !== "login";
            return (
              <button
                key={view}
                className={`menu-item${activeView === view ? " is-active" : ""}`}
                type="button"
                onClick={() => {
                  if (!isLocked) {
                    setActiveView(view);
                  }
                }}
                disabled={isLocked}
                aria-disabled={isLocked}
              >
                {view === "login" ? loginLabel : viewContent[view].title}
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="main-panel">
        <header className="main-header">
          <h1>{activeView === "login" ? loginLabel : content.title}</h1>
          {isAuthenticated ? (
            <div className="health-area">
              <button id="healthBtn" type="button" onClick={handleStateCheck}>
                Check API State
              </button>
              {message ? (
                <span className="health-status">{message}</span>
              ) : null}
            </div>
          ) : null}
        </header>

        <section className="content-card">
          {activeView === "login" ? (
            isAuthenticated ? (
              <div className="logout-panel">
                <p className="logout-text">Press here to log out.</p>
                <button
                  className="logout-button"
                  type="button"
                  onClick={handleLogout}
                >
                  Log out
                </button>
              </div>
            ) : (
              <Login error={loginError} onLogin={handleLogin} />
            )
          ) : activeView === "logs" ? (
            <Logs />
          ) : (
            (content.body ?? (
              <>
                <p>{content.body}</p>
              </>
            ))
          )}
          <div className={`terminal-panel${showTerminal ? " is-active" : ""}`}>
            <Terminal isVisible={showTerminal} />
          </div>
        </section>
      </main>
    </div>
  );
};

export default App;
