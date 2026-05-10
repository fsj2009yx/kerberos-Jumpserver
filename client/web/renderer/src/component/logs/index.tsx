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

const mockPackets: PacketLog[] = [
	{
		id: "packet-1",
		seq: 1,
		timestamp: "2026-05-09T16:09:48.603Z",
		source: "10.0.2.15",
		destination: "10.0.2.20",
		protocol: "KRB5",
		info: "message5 Kerberos Service Request",
		raw: [
			"0000  ---------EncryptedKerberosBlob.--------",
			"0010  -x8fa9sdf89as9df8gasfgasfgasfgasf-----",
			"0020  ----89asfgasfgasf98asfgasf98asf.-----",
			"0030  -----binarycipherstream.------------",
		],
		decoded: [
			"0000  message5 Kerberos Service Request",
			"0010  client=alice",
			"0020  service=terminal",
			"0030  ticket=krbtgt_blob",
			"0040  authenticator=timestamp",
		],
	},
	{
		id: "packet-2",
		seq: 2,
		timestamp: "2026-05-09T16:09:49.091Z",
		source: "10.0.2.20",
		destination: "10.0.2.15",
		protocol: "KRB5",
		info: "message6 Kerberos Service Reply",
		raw: [
			"0000  ---------EncryptedKerberosBlob.--------",
			"0010  -a9c1bbddee2211ffeeddccbb998877-----",
			"0020  ----112233445566778899aabbccdde.---",
			"0030  -----binarycipherstream.------------",
		],
		decoded: [
			"0000  message6 Kerberos Service Reply",
			"0010  client=alice",
			"0020  service=terminal",
			"0030  ticket=service_ticket_blob",
			"0040  session_key=krb_session_key",
		],
	},
	{
		id: "packet-3",
		seq: 3,
		timestamp: "2026-05-09T16:09:49.412Z",
		source: "10.0.2.15",
		destination: "10.0.2.20",
		protocol: "KRB5",
		info: "message7 Authenticator",
		raw: [
			"0000  ---------EncryptedAuthenticator.------",
			"0010  -bbccddeeff001122334455667788-----",
			"0020  ----99aabbccddeeff001122334455.---",
			"0030  -----binarycipherstream.------------",
		],
		decoded: [
			"0000  message7 Authenticator",
			"0010  client=alice",
			"0020  realm=EXAMPLE.COM",
			"0030  timestamp=2026-05-09T16:09:49Z",
			"0040  checksum=0x9e3f",
		],
	},
	{
		id: "packet-4",
		seq: 4,
		timestamp: "2026-05-09T16:09:50.006Z",
		source: "10.0.2.20",
		destination: "10.0.2.15",
		protocol: "KRB5",
		info: "message8 AP-REP",
		raw: [
			"0000  ---------EncryptedApRepBlob.----------",
			"0010  -c0ffee9999aabbccddeeff112233-----",
			"0020  ----44556677889900aabbccddeeff.---",
			"0030  -----binarycipherstream.------------",
		],
		decoded: [
			"0000  message8 AP-REP",
			"0010  client=alice",
			"0020  server=terminal",
			"0030  subkey=krb_subkey",
			"0040  sequence=42",
		],
	},
];

export default function Logs() {
	const useMock = true;
	const [logs, setLogs] = useState<PacketLog[]>(mockPackets);
	const [selectedId, setSelectedId] = useState<string>(mockPackets[0]?.id ?? "");
	const esRef = useRef<EventSource | null>(null);

	useEffect(() => {
		if (useMock) {
			return;
		}
		// need to debug: for some reason when new logs appear it doesn't auto append?
		const es = new EventSource(getLogsUrl());
		esRef.current = es;

		es.onmessage = (event) => {
			try {
				const data = JSON.parse(event.data) as {
					logs: Array<{
						packet_ascii: string;
						decode_packet_ascii: string;
					}>;
				};
				const [packet] = data.logs;
				if (!packet) {
					return;
				}
				const entry: PacketLog = {
					id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
					seq: Date.now(),
					timestamp: new Date().toISOString(),
					source: "10.0.2.15",
					destination: "10.0.2.20",
					protocol: "KRB5",
					info: "Wire packet",
					raw: packet.packet_ascii.split("\n"),
					decoded: packet.decode_packet_ascii.split("\n"),
				};
				// Prepend newest logs so they show at the top.
				setLogs((prev) => [entry, ...prev]);
				setSelectedId(entry.id);
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
	}, [useMock]);

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


