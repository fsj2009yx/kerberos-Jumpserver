import { useEffect, useRef, useState } from "react";
import { animate, stagger } from "motion";

type LoginProps = {
	error: string | null;
	onLogin: (username: string, password: string) => Promise<void>;
};

const Login = ({ error, onLogin }: LoginProps): JSX.Element => {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const shellRef = useRef<HTMLDivElement | null>(null);

	useEffect(() => {
		if (!shellRef.current) {
			return undefined;
		}

		const card = shellRef.current.querySelector<HTMLElement>(".login-card");
		const fields = Array.from(
			shellRef.current.querySelectorAll<HTMLElement>(
				".login-field, .login-button, .login-error, .login-intro, .login-title, .login-eyebrow",
			),
		);
		const orbs = Array.from(
			shellRef.current.querySelectorAll<HTMLElement>(".login-orb"),
		);

		const controls = [] as Array<{ cancel: () => void }>;

		if (card) {
			controls.push(
				animate(
					card,
					{ opacity: [0, 1], y: [26, 0], scale: [0.96, 1] },
					{ duration: 0.6, easing: "ease-out" },
				),
			);
		}

		if (fields.length) {
			controls.push(
				animate(
					fields,
					{ opacity: [0, 1], y: [12, 0] },
					{ delay: stagger(0.06, { start: 0.1 }), duration: 0.45, easing: "ease-out" },
				),
			);
		}

		if (orbs.length) {
			controls.push(
				animate(
					orbs,
					{ opacity: [0, 0.65], scale: [0.85, 1] },
					{ duration: 0.7, easing: "ease-out" },
				),
			);
			orbs.forEach((orb, index) => {
				controls.push(
					animate(
						orb,
						{ y: [0, -18, 0], x: [0, 12, 0] },
						{
							duration: 6 + index * 1.4,
							repeat: Infinity,
							easing: "ease-in-out",
						},
					),
				);
			});
		}

		return () => {
			controls.forEach((control) => control.cancel());
		};
	}, []);

	const handleSubmit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
		event.preventDefault();
		setIsSubmitting(true);
		try {
			await onLogin(username.trim(), password);
		} finally {
			setIsSubmitting(false);
			setPassword("");
		}
	};

	return (
		<div className="login-shell" ref={shellRef}>
			<div className="login-orb login-orb-a" aria-hidden="true" />
			<div className="login-orb login-orb-b" aria-hidden="true" />
			<div className="login-orb login-orb-c" aria-hidden="true" />

			<div className="login-card">
				<div className="login-card-header">
					<p className="login-eyebrow">Kerberos Client</p>
					<h1 className="login-title">Secure Access</h1>
					<p className="login-intro">Sign in to continue.</p>
				</div>

				<form className="login-form" onSubmit={handleSubmit}>
					<div className="login-field">
						<label htmlFor="username">Username</label>
						<input
							id="username"
							className="login-input"
							type="text"
							autoComplete="username"
							value={username}
							onChange={(event) => setUsername(event.target.value)}
							disabled={isSubmitting}
						/>
					</div>

					<div className="login-field">
						<label htmlFor="password">Password</label>
						<input
							id="password"
							className="login-input"
							type="password"
							autoComplete="current-password"
							value={password}
							minLength={8}
							maxLength={8}
							onChange={(event) => setPassword(event.target.value)}
							disabled={isSubmitting}
						/>
					</div>

					<button className="login-button" type="submit" disabled={isSubmitting}>
						{isSubmitting ? "Signing in..." : "Sign In"}
					</button>

					{error ? <div className="login-error">{error}</div> : null}
				</form>
			</div>
		</div>
	);
};

export default Login;
