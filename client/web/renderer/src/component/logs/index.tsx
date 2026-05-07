import { useEffect, useRef, useState } from "react";
import { getLogsUrl } from "@/utils/api_calls";

type LogEntry = {
	id: string;
	timestamp: string;
	message: string;
};

export default function Logs() {
	const [logs, setLogs] = useState<LogEntry[]>([]);
	const esRef = useRef<EventSource | null>(null);

	useEffect(() => {
		// need to debug: for some reason when new logs appear it doesn't auto append?
		const es = new EventSource(getLogsUrl());
		esRef.current = es;

		es.onmessage = (event) => {
			try {
				const data = JSON.parse(event.data) as {
					timestamp: string;
					message: string;
				};
				const entry: LogEntry = {
					// Create a randomized ID
					id: `${data.timestamp}-${Math.random().toString(36).slice(2)}`,
					timestamp: data.timestamp,
					message: data.message,
				};
                console.log(entry)
				// Prepend newest logs so they show at the top.
				setLogs((prev) => [entry, ...prev]);
			} catch (e) {
				// Ignore malformed events.
                console.log("es.onmessage error: " + e)
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
		<section>
			<h2>Logs</h2>
			<div>
				{logs.map((log) => (
					<div key={log.id}>
						<span>{log.timestamp}</span>
						<span> - </span>
						<span>{log.message}</span>
					</div>
				))}
			</div>
		</section>
	);
}


