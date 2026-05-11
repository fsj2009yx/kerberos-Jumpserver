import { CSSProperties, useEffect, useRef, useState } from "react";
import { getLogsUrl } from "@/utils/api_calls";

type PacketLog = {
	id: string;
	seq: number;
	timestamp: string;
	source: string;
	destination: string;
	protocol: string;
	info: string;
	raw: string[];
	decoded: string[];
};

const decodeRawToAscii = (rawLines: string[]): string[] => {
	return rawLines.map((line) => {
		const trimmed = line.trim();
		if (!trimmed) {
			return line;
		}
		const offsetMatch = trimmed.match(/^([0-9a-fA-F]{4})\s+/);
		const offset = offsetMatch?.[1] ?? "";
		const withoutOffset = trimmed.replace(/^([0-9a-fA-F]{4})\s+/, "");
		const hexPart = withoutOffset.split(/\s{2,}/)[0] ?? "";
		const bytes = hexPart.match(/[0-9a-fA-F]{2}/g) ?? [];
		const ascii = bytes
			.map((pair) => parseInt(pair, 16))
			.map((value) => (value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : "."))
			.join("");
		return offset ? `${offset}  ${ascii}` : ascii;
	});
};

const normalizePackets = (payload: unknown): PacketLog[] => {
	if (!payload || typeof payload !== "object") {
		return [];
	}
	if (Array.isArray(payload)) {
		return payload as PacketLog[];
	}
	if ("logs" in payload && Array.isArray((payload as { logs?: unknown }).logs)) {
		return (payload as { logs: PacketLog[] }).logs;
	}
	return [payload as PacketLog];
};

export default function Logs() {
	const [logs, setLogs] = useState<PacketLog[]>([]);
	const [selectedId, setSelectedId] = useState<string>("");
	const esRef = useRef<EventSource | null>(null);

	useEffect(() => {
		// need to debug: for some reason when new logs appear it doesn't auto append?
		const es = new EventSource(getLogsUrl());
		esRef.current = es;

		es.onmessage = (event) => {
			try {
				const payload = JSON.parse(event.data) as unknown;
				const packets = normalizePackets(payload);
				if (!packets.length || !packets) {
					return;
				}
				const entries: PacketLog[] = packets
					.filter((packet) => Boolean(packet?.protocol))
					.map((packet) => {
					const rawLines = packet.raw ?? [];
					const decodedLines = packet.decoded?.length
						? packet.decoded
						: decodeRawToAscii(rawLines);
					return {
						id: packet.id || `${Date.now()}-${Math.random().toString(36).slice(2)}`,
						seq: packet.seq ?? Date.now(),
						timestamp: packet.timestamp ?? new Date().toISOString(),
						source: packet.source ?? "",
						destination: packet.destination ?? "",
						protocol: packet.protocol ?? "",
						info: packet.info ?? "",
						raw: rawLines,
						decoded: decodedLines,
					};
					});
				// Prepend newest logs so they show at the top.
				setLogs((prev) => [...entries, ...prev]);
				setSelectedId((prevSelected) => entries[0]?.id ?? prevSelected);
			} catch (e) {
				// Ignore malformed events.
				console.log("es.onmessage error: " + e);
			}
		};

		es.onerror = (err) => {
			// Let the browser handle reconnection; we keep the instance alive.
            console.log("Event Source connection error: ", err)
		};

		return () => {
			es.close();
			esRef.current = null;
		};
	}, []);

	return (
		<section className=" logs-panel">
			{/* <header className="logs-header">
				<div>
					<p className="logs-kicker">Packet Log Console</p>
					<h2>Kerberos Wire Capture</h2>
				</div>
				<span className="logs-status">Mock stream active</span>
			</header> */}
			<div className="logs-surface">
				<div className="logs-layout">
					<div className="logs-list">
						<div className="logs-list-header">
							<span>No.</span>
							<span>Timestamp</span>
							<span>Source</span>
							<span>Destination</span>
							<span>Protocol</span>
							<span>Info</span>
						</div>
						{logs.map((log) => (
							<button
								key={log.id}
								type="button"
								className={`logs-entry ${log.id === selectedId ? "is-active" : ""}`}
								onClick={() => setSelectedId(log.id)}
							>
								<span className="logs-cell">{log.seq}</span>
								<span className="logs-cell logs-time">{log.timestamp}</span>
								<span className="logs-cell">{log.source}</span>
								<span className="logs-cell">{log.destination}</span>
								<span className="logs-cell logs-chip">{log.protocol}</span>
								<span className="logs-cell logs-title">{log.info}</span>
							</button>
						))}
					</div>
					<div className="logs-detail">
						{(() => {
							const active = logs.find((log) => log.id === selectedId);
							if (!active) {
								return (
									<div className="logs-empty">Select a log entry to inspect the packet.</div>
								);
							}
							return (
								<div className="logs-grid">
									<div className="logs-column">
										<h3>Packet Details</h3>
										<div className="logs-box">
											{active.decoded.map((line, index) => (
												<div
													key={`${active.id}-decoded-${index}`}
													className="logs-line"
													style={{ "--i": index } as CSSProperties}
												>
													{line}
												</div>
											))}
										</div>
									</div>
									<div className="logs-column">
										<h3>Packet Bytes</h3>
										<div className="logs-box is-decoded">
											{active.raw.map((line, index) => (
												<div
													key={`${active.id}-raw-${index}`}
													className="logs-line"
													style={{ "--i": index } as CSSProperties}
												>
													{line}
												</div>
											))}
										</div>
									</div>
								</div>
							);
						})()}
					</div>
				</div>
			</div>
		</section>
	);
}


