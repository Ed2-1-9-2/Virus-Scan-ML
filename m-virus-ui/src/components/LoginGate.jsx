import React, { useMemo, useState } from 'react';
import axios from 'axios';
import './LoginGate.css';

const USERNAME_OR_EMAIL_RE = /^(?:[a-zA-Z0-9._-]{3,64}|[^\s@]+@[^\s@]+\.[^\s@]{2,})$/;

const LoginGate = ({ apiBase, onAuthenticated }) => {
  const [mode, setMode] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const iconSrc = `${process.env.PUBLIC_URL || ''}/malware-observatory-icon.svg`;

  const title = useMemo(() => (
    mode === 'login' ? 'Autentificare' : 'Creare cont'
  ), [mode]);

  const submitLabel = mode === 'login' ? 'Login' : 'Register';
  const switchLabel = mode === 'login' ? 'Nu ai cont? Creeaza unul' : 'Ai deja cont? Intra in aplicatie';

  const validate = () => {
    const u = username.trim();
    if (!USERNAME_OR_EMAIL_RE.test(u)) {
      return 'Username/email invalid. Foloseste username (3-64) sau o adresa de email valida.';
    }
    if (password.length < 8) {
      return 'Parola trebuie sa aiba cel putin 8 caractere.';
    }
    if (mode === 'register' && password !== confirmPassword) {
      return 'Parolele nu coincid.';
    }
    return '';
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setBusy(true);
    setError('');
    try {
      const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';
      const response = await axios.post(`${apiBase}${endpoint}`, {
        username: username.trim(),
        password,
      }, { timeout: 30000 });

      const token = response?.data?.token;
      const authUsername = response?.data?.username;
      const isAdmin = Boolean(response?.data?.is_admin);
      if (!token || !authUsername) {
        throw new Error('Raspuns invalid de la server.');
      }

      onAuthenticated({ token, username: authUsername, is_admin: isAdmin });
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setError(detail || err?.message || 'Autentificarea a esuat.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-root">
      <div className="login-card">
        <div className="login-brand">
          <img className="login-brand-icon" src={iconSrc} alt="M-Virus icon" />
          <div>
            <h1 className="login-title">M-Virus Access</h1>
            <p className="login-subtitle">Conecteaza-te pentru a accesa dashboard-ul de analiza malware.</p>
          </div>
        </div>

        <h2 className="login-mode">{title}</h2>

        <form onSubmit={handleSubmit} className="login-form">
          <label htmlFor="mv-username">Username sau email</label>
          <input
            id="mv-username"
            type="text"
            value={username}
            autoComplete="username"
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
            required
          />

          <label htmlFor="mv-password">Parola</label>
          <input
            id="mv-password"
            type="password"
            value={password}
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
            required
          />

          {mode === 'register' && (
            <>
              <label htmlFor="mv-password-confirm">Confirmare parola</label>
              <input
                id="mv-password-confirm"
                type="password"
                value={confirmPassword}
                autoComplete="new-password"
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={busy}
                required
              />
            </>
          )}

          {error && <div className="login-error">{error}</div>}

          <button type="submit" className="login-submit" disabled={busy}>
            {busy ? 'Se proceseaza...' : submitLabel}
          </button>
        </form>

        <button
          type="button"
          className="login-switch"
          disabled={busy}
          onClick={() => {
            setMode((prev) => (prev === 'login' ? 'register' : 'login'));
            setError('');
          }}
        >
          {switchLabel}
        </button>
      </div>
    </div>
  );
};

export default LoginGate;
