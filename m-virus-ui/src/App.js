import React, { useCallback, useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import MalwareDetector from './components/MalwareDetector';
import LoginGate from './components/LoginGate';
import AdminPage from './components/AdminPage';

const AUTH_TOKEN_STORAGE_KEY = 'm-virus-auth-token';
const AUTH_USER_STORAGE_KEY = 'm-virus-auth-user';
const AUTH_ADMIN_STORAGE_KEY = 'm-virus-auth-is-admin';

const routeFromPath = () => {
  const path = window.location.pathname.toLowerCase();
  return path.startsWith('/admin') || path.startsWith('/app/admin') ? 'admin' : 'app';
};

const pathForRoute = (route) => {
  const path = window.location.pathname.toLowerCase();
  const appPrefix = path.startsWith('/app') ? '/app' : '';
  if (route === 'admin') return appPrefix ? `${appPrefix}/admin` : '/admin';
  return appPrefix || '/';
};

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
  const [isAdmin, setIsAdmin] = useState(() => window.localStorage.getItem(AUTH_ADMIN_STORAGE_KEY) === '1');
  const [route, setRoute] = useState(routeFromPath);

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

  useEffect(() => {
    window.localStorage.setItem(AUTH_ADMIN_STORAGE_KEY, isAdmin ? '1' : '0');
  }, [isAdmin]);

  useEffect(() => {
    const onPopState = () => setRoute(routeFromPath());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const syncProfile = async () => {
      if (!token) return;
      try {
        const response = await axios.get(`${api}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 15000,
        });
        if (cancelled) return;
        const username = String(response?.data?.username || '').trim();
        if (username) setCurrentUser(username);
        setIsAdmin(Boolean(response?.data?.is_admin));
      } catch (_) {
        if (cancelled) return;
        setToken('');
        setCurrentUser('');
        setIsAdmin(false);
        setAxiosAuthorization('');
      }
    };
    syncProfile();
    return () => { cancelled = true; };
  }, [api, token]);

  const navigate = useCallback((nextRoute) => {
    const nextPath = pathForRoute(nextRoute);
    if (window.location.pathname !== nextPath) {
      window.history.pushState({}, '', nextPath);
    }
    setRoute(nextRoute);
  }, []);

  const handleAuthenticated = ({ token: authToken, username, is_admin: isAdminFlag = false }) => {
    setToken(String(authToken || ''));
    setCurrentUser(String(username || ''));
    setIsAdmin(Boolean(isAdminFlag));
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
    setIsAdmin(false);
    setAxiosAuthorization('');
  };

  // Keep axios auth header synchronized before rendering child components.
  setAxiosAuthorization(token);

  if (!token) {
    return <LoginGate apiBase={api} onAuthenticated={handleAuthenticated} />;
  }

  if (route === 'admin') {
    return (
      <AdminPage
        apiBase={api}
        currentUser={currentUser}
        isAdmin={isAdmin}
        onBackToApp={() => navigate('app')}
        onLogout={handleLogout}
      />
    );
  }

  return (
    <MalwareDetector
      currentUser={currentUser}
      onLogout={handleLogout}
      isAdmin={isAdmin}
      onOpenAdmin={() => navigate('admin')}
    />
  );
}

export default App;
