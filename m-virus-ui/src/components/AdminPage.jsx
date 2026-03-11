import React, { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import './AdminPage.css';

const REFRESH_MS = 12000;

const AdminPage = ({
  apiBase,
  currentUser = '',
  isAdmin = false,
  onBackToApp = null,
  onLogout = null,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [data, setData] = useState(null);

  const loadAdmin = useCallback(async () => {
    setError('');
    try {
      const response = await axios.get(`${apiBase}/admin`, { timeout: 30000 });
      setData(response?.data || null);
      setLoading(false);
      return true;
    } catch (err) {
      const status = err?.response?.status;
      const detail = err?.response?.data?.detail;
      if (status === 403) {
        setError('Acces interzis. Pagina /admin este disponibila doar pentru conturi admin.');
      } else if (status === 401) {
        setError('Sesiune invalida. Fa login din nou.');
      } else {
        setError(detail || err?.message || 'Nu s-au putut incarca datele admin.');
      }
      setLoading(false);
      return false;
    }
  }, [apiBase]);

  useEffect(() => {
    loadAdmin();
    const timer = setInterval(loadAdmin, REFRESH_MS);
    return () => clearInterval(timer);
  }, [loadAdmin]);

  return (
    <div className="admin-root">
      <div className="admin-shell">
        <header className="admin-header">
          <div>
            <p className="admin-kicker">secure://admin/console</p>
            <h1>Admin Console</h1>
            <p className="admin-subtitle">
              Monitorizare utilizatori, sesiuni active si stare runtime.
            </p>
          </div>
          <div className="admin-actions">
            <button type="button" onClick={loadAdmin}>Refresh</button>
            {typeof onBackToApp === 'function' && (
              <button type="button" onClick={onBackToApp}>Inapoi la App</button>
            )}
            {typeof onLogout === 'function' && (
              <button type="button" onClick={onLogout}>Logout</button>
            )}
          </div>
        </header>

        <div className="admin-meta">
          <span><strong>User:</strong> {currentUser || 'N/A'}</span>
          <span><strong>Admin:</strong> {isAdmin ? 'Yes' : 'No'}</span>
        </div>

        {loading && <div className="admin-panel">Se incarca datele admin...</div>}
        {!loading && error && <div className="admin-panel admin-error">{error}</div>}

        {!loading && !error && data && (
          <>
            <section className="admin-grid">
              <article className="admin-panel">
                <h2>Identitate</h2>
                <p><strong>admin_user:</strong> {data.admin_user || 'N/A'}</p>
                <p><strong>is_admin:</strong> {String(Boolean(data.is_admin))}</p>
                <p><strong>timestamp:</strong> {data.timestamp || 'N/A'}</p>
              </article>

              <article className="admin-panel">
                <h2>Utilizatori & sesiuni</h2>
                <p><strong>users_count:</strong> {String(data.users_count ?? 'N/A')}</p>
                <p><strong>active_sessions_count:</strong> {String(data.active_sessions_count ?? 'N/A')}</p>
              </article>

              <article className="admin-panel">
                <h2>Modele incarcate</h2>
                <p>{Array.isArray(data.loaded_prediction_models) && data.loaded_prediction_models.length > 0
                  ? data.loaded_prediction_models.join(', ')
                  : 'N/A'}
                </p>
              </article>

              <article className="admin-panel">
                <h2>Modele indisponibile</h2>
                <pre>{JSON.stringify(data.unavailable_prediction_models || {}, null, 2)}</pre>
              </article>
            </section>

            <section className="admin-panel">
              <h2>Raw /admin response</h2>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </section>
          </>
        )}
      </div>
    </div>
  );
};

export default AdminPage;
