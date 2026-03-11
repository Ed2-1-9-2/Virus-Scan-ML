import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import MalwareDetector from './components/MalwareDetector';
import LoginGate from './components/LoginGate';

const AUTH_TOKEN_STORAGE_KEY = 'm-virus-auth-token';
const AUTH_USER_STORAGE_KEY = 'm-virus-auth-user';

const apiBase = () => {
  const env = String(process.env.REACT_APP_API_URL || '').trim();
  if (env) return env.replace(/\/+$/, '');
  const { protocol, hostname, host, port } = window.location;
  if (port && port !== '3000') return `${protocol}//${host}`;
  return `${protocol}//${hostname || '127.0.0.1'}:8000`;
};

const setAxiosAuthorization = (token) => {
  if (token) {
    axios.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete axios.defaults.headers.common.Authorization;
  }
};

function App() {
  const api = useMemo(() => apiBase(), []);
  const [token, setToken] = useState(() => window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY) || '');
  const [currentUser, setCurrentUser] = useState(() => window.localStorage.getItem(AUTH_USER_STORAGE_KEY) || '');

  useEffect(() => {
    setAxiosAuthorization(token);
    if (token) {
      window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token);
    } else {
      window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    }
  }, [token]);

  useEffect(() => {
    if (currentUser) {
      window.localStorage.setItem(AUTH_USER_STORAGE_KEY, currentUser);
    } else {
      window.localStorage.removeItem(AUTH_USER_STORAGE_KEY);
    }
  }, [currentUser]);

  const handleAuthenticated = ({ token: authToken, username }) => {
    setToken(String(authToken || ''));
    setCurrentUser(String(username || ''));
  };

  const handleLogout = async () => {
    if (token) {
      try {
        await axios.post(`${api}/auth/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 15000,
        });
      } catch (_) {
        // Ignore backend logout errors, clear local auth anyway.
      }
    }

    setToken('');
    setCurrentUser('');
    setAxiosAuthorization('');
  };

  // Keep axios auth header synchronized before rendering child components.
  setAxiosAuthorization(token);

  if (!token) {
    return <LoginGate apiBase={api} onAuthenticated={handleAuthenticated} />;
  }

  return (
    <MalwareDetector
      currentUser={currentUser}
      onLogout={handleLogout}
    />
  );
}

export default App;
