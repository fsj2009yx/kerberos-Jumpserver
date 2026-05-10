import { useState } from "react";

type LoginProps = {
	error: string | null;
	onLogin: (username: string, password: string) => Promise<void>;
};

const Login = ({ error, onLogin }: LoginProps): JSX.Element => {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);

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
		<form className="login-form" onSubmit={handleSubmit}>
			<p className="login-intro">Sign in to continue.</p>

			<div className="login-field">
				<label htmlFor="username">Username</label>
				<input
					id="username"
					className="login-input"
					type="text"
					autoComplete="username"
					value={username}
					onChange={(event) => setUsername(event.target.value)}
					required
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
					required
					disabled={isSubmitting}
				/>
			</div>

			<button className="login-button" type="submit" disabled={isSubmitting}>
				{isSubmitting ? "Signing in..." : "Sign In"}
			</button>

			{error ? <div className="login-error">{error}</div> : null}
		</form>
	);
};

export default Login;
