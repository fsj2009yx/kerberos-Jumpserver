import { useEffect, useMemo, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css"

type ConnectionStatus = "disconnected" | "connecting" | "connected" | "error";

const WS_PTY_URL = "ws://127.0.0.1:9883/ws/pty";

const encodeBase64 = (value: string): string => {
	const bytes = new TextEncoder().encode(value);
	let binary = "";
	bytes.forEach((byte) => {
		binary += String.fromCharCode(byte);
	});
	return btoa(binary);
};

const decodeBase64 = (value: string): string => {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}
	return new TextDecoder().decode(bytes);
};

type TerminalViewProps = {
	isVisible?: boolean;
	isAuthenticated: boolean;
};

const TerminalView = ({ isVisible = true, isAuthenticated }: TerminalViewProps): JSX.Element => {
	const containerRef = useRef<HTMLDivElement | null>(null);
	const terminalRef = useRef<Terminal | null>(null);
	const fitAddonRef = useRef<FitAddon | null>(null);
	const sessionIdRef = useRef<string | null>(null);
	const pendingInputRef = useRef<string[]>([]);

	const [status, setStatus] = useState<ConnectionStatus>("disconnected");
	const [errorMessage, setErrorMessage] = useState<string | null>(null);

	const statusLabel = useMemo(() => {
		switch (status) {
			case "connecting":
				return "Connecting";
			case "connected":
				return "Connected";
			case "error":
				return "Error";
			default:
				return "Disconnected";
		}
	}, [status]);

	const focusTerminal = (): void => {
		terminalRef.current?.focus();
	};

	useEffect(() => {
		if (!containerRef.current || !isAuthenticated) {
			if (!isAuthenticated) {
				setStatus("disconnected");
				setErrorMessage("Login required to open terminal.");
				sessionIdRef.current = null;
				pendingInputRef.current = [];
			}
			return undefined;
		}

		const terminal = new Terminal({
			cursorBlink: true,
			convertEol: true,
			fontFamily: "Menlo, Consolas, 'Courier New', monospace",
			fontSize: 14,
			theme: {
				background: "#0b1220",
				foreground: "#d2e3ff",
				cursor: "#6ea2ff",
				selectionBackground: "rgba(110, 162, 255, 0.35)"
			}
		});

		const fitAddon = new FitAddon();
		terminal.loadAddon(fitAddon);
		terminal.open(containerRef.current);
		fitAddon.fit();
		terminal.focus();

		terminalRef.current = terminal;
		fitAddonRef.current = fitAddon;

		sessionIdRef.current = null;
		pendingInputRef.current = [];

		setStatus("connecting");
		setErrorMessage(null);

		const socket = new WebSocket(WS_PTY_URL);

		const sendJson = (payload: Record<string, unknown>): void => {
			if (socket.readyState === WebSocket.OPEN) {
				socket.send(JSON.stringify(payload));
			}
		};

		const flushPendingInput = (): void => {
			if (!sessionIdRef.current || pendingInputRef.current.length === 0) {
				return;
			}

			const sessionId = sessionIdRef.current;
			const chunks = pendingInputRef.current.splice(0, pendingInputRef.current.length);
			chunks.forEach((chunk) => {
				sendJson({ op: "input", session_id: sessionId, data: encodeBase64(chunk) });
			});
		};

		const dataDisposable = terminal.onData((data) => {
			if (!sessionIdRef.current) {
				pendingInputRef.current.push(data);
				return;
			}

			sendJson({ op: "input", session_id: sessionIdRef.current, data: encodeBase64(data) });
		});

		const resizeDisposable = terminal.onResize(({ cols, rows }) => {
			if (!sessionIdRef.current) {
				return;
			}

			sendJson({ op: "resize", session_id: sessionIdRef.current, cols, rows });
		});

		socket.onopen = () => {
			setStatus("connected");
			terminal.writeln("Connected. Opening PTY session...");
			const cols = terminal.cols || 80;
			const rows = terminal.rows || 24;
			sendJson({ op: "open", cols, rows, term: "xterm-256color" });
		};

		socket.onmessage = (event) => {
			let payload: { event?: string; session_id?: string; data?: string; exit_code?: number; message?: string };
			try {
				payload = JSON.parse(event.data as string) as typeof payload;
			} catch (error) {
				return;
			}

			switch (payload.event) {
				case "open_ok": {
					sessionIdRef.current = payload.session_id ?? null;
					terminal.writeln(`Session ready: ${payload.session_id ?? "unknown"}`);
					flushPendingInput();
					break;
				}
				case "output": {
					if (!payload.session_id || payload.session_id !== sessionIdRef.current) {
						return;
					}
					const raw = payload.data ?? "";
					try {
						terminal.write(raw ? decodeBase64(raw) : "");
					} catch {
						terminal.write(raw);
					}
					break;
				}
				case "exit": {
					terminal.writeln(`\r\nSession closed (code ${payload.exit_code ?? "?"}).`);
					sessionIdRef.current = null;
					break;
				}
				case "error": {
					setStatus("error");
					const errorText = payload.message ?? "Unknown error";
					if (payload.data) {
						try {
							terminal.writeln(`\r\nError: ${decodeBase64(payload.data)}`);
						} catch {
							terminal.writeln(`\r\nError: ${payload.data}`);
						}
					} else {
						terminal.writeln(`\r\nError: ${errorText}`);
					}
					setErrorMessage(errorText);
					break;
				}
				default:
					break;
			}
		};

		socket.onerror = () => {
			setStatus("error");
			setErrorMessage("WebSocket error");
			terminal.writeln("\r\nWebSocket error.");
		};

		socket.onclose = () => {
			setStatus("disconnected");
			terminal.writeln("\r\nConnection closed.");
			sessionIdRef.current = null;
		};

		const handleWindowResize = (): void => {
			fitAddon.fit();
		};

		window.addEventListener("resize", handleWindowResize);

		return () => {
			window.removeEventListener("resize", handleWindowResize);
			dataDisposable.dispose();
			resizeDisposable.dispose();
			if (socket.readyState === WebSocket.OPEN && sessionIdRef.current) {
				sendJson({ op: "close", session_id: sessionIdRef.current });
			}
			socket.close();
			terminal.dispose();
			fitAddonRef.current = null;
			terminalRef.current = null;
		};
	}, [isAuthenticated]);

	useEffect(() => {
		if (!isVisible) {
			return undefined;
		}
		if (!fitAddonRef.current || !terminalRef.current) {
			return undefined;
		}

		const frame = window.requestAnimationFrame(() => {
			fitAddonRef.current?.fit();
			terminalRef.current?.focus();
		});

		return () => window.cancelAnimationFrame(frame);
	}, [isVisible]);

	return (
		<div className="terminal-shell">
			<div className="terminal-toolbar">
				<div className="terminal-status-group">
					<div className={`terminal-status status-${status}`}>{statusLabel}</div>
					{errorMessage ? (
						<div className="terminal-error-inline">{errorMessage}</div>
					) : null}
				</div>
			</div>
			<div
				className="terminal-body"
				ref={containerRef}
				tabIndex={0}
				onMouseDown={focusTerminal}
				onTouchStart={focusTerminal}
				onFocus={focusTerminal}
			/>
		</div>
	);
};

export default TerminalView;
