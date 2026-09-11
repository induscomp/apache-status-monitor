import { StrictMode, useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  ArrowRight,
  Archive,
  Check,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Database,
  Globe2,
  Layers3,
  LockKeyhole,
  LogOut,
  MoreHorizontal,
  Pencil,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Server as ServerIcon,
  ShieldCheck,
  X,
} from 'lucide-react';
import { api, ApiError } from './api';
import { Setup } from './Setup';
import { ApacheDiagnostics } from './ApacheDiagnostics';
import type { Health, Page, Server, Service, Session } from './api';
import './styles.css';

const EMPTY = { items: [], total: 0 };
const KIND = { apache_status: 'Apache Status', mrtg: 'MRTG' };
const STATUS = {
  waiting: 'Esperando primera recogida',
  ok: 'Recogida correcta',
  partial: 'Datos parciales',
  error: 'Error de recogida',
  stale: 'Datos desactualizados',
  pending: 'Pendiente de recolector',
  paused: 'Pausado',
  archived: 'Archivado',
};
const message = (error: unknown) =>
  error instanceof Error ? error.message : 'No se pudo completar la operación.';

function Brand() {
  return (
    <div className="brand">
      <span className="brand-icon">
        <Activity size={23} />
      </span>
      <span>
        Apache<span className="brand-sub">STATUS MONITOR</span>
      </span>
    </div>
  );
}

function Dialog({
  title,
  children,
  close,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog ref={ref} aria-labelledby="dialog-title" onCancel={close}>
      <div className="dialog-head">
        <h2 id="dialog-title">{title}</h2>
        <button className="icon-button" aria-label="Cerrar" onClick={close}>
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}

function Login({
  ready,
  initialError,
}: {
  ready: (session: Session) => void;
  initialError: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(initialError);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    const data = new FormData(event.currentTarget);
    try {
      ready(await api<Session>('/auth/login', undefined, 'POST', Object.fromEntries(data)));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-layout">
      <section className="login-story">
        <Brand />
        <div>
          <span className="eyebrow light">OBSERVAR · ENTENDER · DECIDIR</span>
          <h1>
            Tu infraestructura,
            <br />
            <em>en contexto.</em>
          </h1>
          <p>Un lugar para conectar tus servidores y entender la actividad de cada servicio.</p>
          <div className="signal-art" aria-hidden="true">
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
            <span />
          </div>
        </div>
        <span className="login-foot">OPEN SOURCE / APACHE STATUS MONITOR</span>
      </section>
      <section className="login-panel">
        <div className="login-box">
          <div className="square-icon">
            <LockKeyhole />
          </div>
          <span className="eyebrow">ACCESO AL PANEL</span>
          <h2>Bienvenido de nuevo</h2>
          <p className="muted">Accede con tu cuenta de administrador y tu segundo factor.</p>
          <form onSubmit={submit}>
            <label>
              Email
              <input name="email" type="email" autoComplete="username" required maxLength={254} />
            </label>
            <label>
              Contraseña
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
                maxLength={1024}
              />
            </label>
            <label>
              Código de autenticación o recuperación
              <input
                name="code"
                autoComplete="one-time-code"
                aria-describedby="login-code-help"
                required
                minLength={6}
                maxLength={64}
                spellCheck={false}
              />
            </label>
            <p id="login-code-help" className="setup-help">
              Abre tu aplicación autenticadora y escribe los seis dígitos de la cuenta Apache Status
              Monitor. Cambian cada 30 segundos. También puedes usar uno de los códigos de
              recuperación guardados al crear el usuario.
            </p>
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <button className="primary wide" disabled={busy}>
              {busy ? 'Verificando…' : 'Entrar al panel'}
              <ArrowRight size={18} />
            </button>
          </form>
          <p className="login-note">
            <ShieldCheck size={17} /> Sesión protegida con verificación en dos pasos.
          </p>
          <details className="setup-help">
            <summary>¿No tienes configurado el autenticador?</summary>
            <p>
              Durante el alta, la terminal muestra un código QR. En tu aplicación autenticadora,
              pulsa añadir cuenta y escanear QR; después confirma con los seis dígitos que genera.
            </p>
            <p>
              Si ya creaste el usuario pero perdiste esa cuenta, ejecuta desde la carpeta del
              proyecto en Kakarot, con el despliegue local:
            </p>
            <p>
              <code>
                docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli
                reset-mfa
              </code>
            </p>
            <p>
              Te pedirá tu contraseña actual y mostrará un nuevo QR para escanear. Puedes hacerlo
              sin iniciar sesión en la web. Al completarlo se sustituyen los códigos de recuperación
              y se cierran las sesiones abiertas. Guarda los nuevos códigos en tu gestor de
              contraseñas.
            </p>
          </details>
        </div>
      </section>
    </main>
  );
}

function ServerForm({
  current,
  save,
  close,
}: {
  current?: Server;
  save: (body: unknown) => Promise<void>;
  close: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    try {
      await save({
        name: data.get('name'),
        description: data.get('description'),
        tags: String(data.get('tags'))
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean),
        ...(current ? { archived: current.archived } : {}),
      });
      close();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog title={current ? 'Editar servidor' : 'Añadir servidor'} close={close}>
      <form onSubmit={submit}>
        <p className="muted">Agrupa aquí los servicios de una misma máquina.</p>
        <label>
          Nombre del servidor
          <input
            name="name"
            defaultValue={current?.name}
            required
            maxLength={100}
            placeholder="Servidor de producción"
          />
        </label>
        <label>
          Descripción
          <textarea
            name="description"
            defaultValue={current?.description}
            maxLength={1000}
            rows={3}
            placeholder="Ubicación, finalidad o notas de este servidor"
          />
        </label>
        <label>
          Etiquetas
          <input
            name="tags"
            defaultValue={current?.tags.join(', ')}
            placeholder="producción, web"
          />
          <small>Separadas por comas. Máximo 10 etiquetas de 30 caracteres.</small>
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={close}>
            Cancelar
          </button>
          <button className="primary" disabled={busy}>
            {busy ? 'Guardando…' : 'Guardar servidor'}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function ServiceForm({
  current,
  save,
  close,
}: {
  current?: Service;
  save: (body: unknown) => Promise<void>;
  close: () => void;
}) {
  const [kind, setKind] = useState(current?.kind ?? 'apache_status');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    const username = String(data.get('username') ?? '');
    const password = String(data.get('password') ?? '');
    const body = {
      name: data.get('name'),
      url: data.get('url'),
      interval_seconds: Number(data.get('interval')) * 60,
      enabled: data.has('enabled'),
      options: { apache_auto: kind === 'apache_status' && data.has('apache_auto') },
      ...(username || password ? { credentials: { username, password } } : {}),
      ...(current
        ? { archived: current.archived, clear_credentials: data.has('clear_credentials') }
        : { kind }),
    };
    try {
      await save(body);
      close();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog title={current ? 'Editar servicio' : 'Añadir servicio'} close={close}>
      <form onSubmit={submit}>
        <label>
          Tipo de servicio
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as Service['kind'])}
            disabled={!!current}
          >
            <option value="apache_status">Apache Status</option>
            <option value="mrtg">MRTG</option>
          </select>
        </label>
        <label>
          Nombre del servicio
          <input
            name="name"
            defaultValue={current?.name}
            required
            maxLength={100}
            placeholder={kind === 'mrtg' ? 'Estadísticas MRTG' : 'Apache principal'}
          />
        </label>
        <label>
          {kind === 'mrtg' ? 'URL del índice MRTG' : 'URL base de Apache Status'}
          <input
            name="url"
            type="url"
            defaultValue={current?.url}
            required
            maxLength={2048}
            placeholder={
              kind === 'mrtg'
                ? 'https://servidor.example/mrtg/'
                : 'https://servidor.example/server-status'
            }
          />
          <small>
            El origen debe estar autorizado en la configuración del despliegue. Sin credenciales ni
            parámetros en la URL.
          </small>
        </label>
        {kind === 'mrtg' && (
          <p className="info-note">
            MRTG se leerá siguiendo los enlaces de las imágenes hasta las páginas con estadísticas
            numéricas. El recolector se incorporará en SMON-004.
          </p>
        )}
        <label>
          Intervalo (minutos)
          <input
            name="interval"
            type="number"
            min={1}
            max={1440}
            step={1}
            defaultValue={(current?.interval_seconds ?? 300) / 60}
            required
          />
        </label>
        {kind === 'apache_status' && (
          <label className="check-label">
            <input
              name="apache_auto"
              type="checkbox"
              defaultChecked={current?.options.apache_auto ?? true}
            />
            Incluir resumen de métricas de Apache (?auto)
          </label>
        )}
        <label className="check-label">
          <input name="enabled" type="checkbox" defaultChecked={current?.enabled ?? true} />
          Habilitar cuando esté disponible el recolector
        </label>
        <details>
          <summary>Autenticación del endpoint (opcional)</summary>
          <p className="muted small">
            Solo con HTTPS.{' '}
            {current?.has_credentials
              ? 'Ya hay credenciales guardadas; deja los campos vacíos para conservarlas.'
              : 'Deja los campos vacíos si el endpoint no requiere autenticación.'}
          </p>
          <label>
            Usuario del endpoint
            <input name="username" autoComplete="off" maxLength={200} />
          </label>
          <label>
            Contraseña del endpoint
            <input name="password" type="password" autoComplete="new-password" maxLength={1024} />
          </label>
          {current?.has_credentials && (
            <label className="check-label">
              <input name="clear_credentials" type="checkbox" />
              Borrar las credenciales guardadas
            </label>
          )}
        </details>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={close}>
            Cancelar
          </button>
          <button className="primary" disabled={busy}>
            {busy ? 'Guardando…' : 'Guardar servicio'}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function Workspace({ session, expired }: { session: Session; expired: () => void }) {
  const [diagnostic, setDiagnostic] = useState<Service | null>(null);
  const [servers, setServers] = useState<Page<Server>>(EMPTY);
  const [services, setServices] = useState<Page<Service>>(EMPTY);
  const [selected, setSelected] = useState<string | null>(null);
  const [serverOffset, setServerOffset] = useState(0);
  const [serviceOffset, setServiceOffset] = useState(0);
  const [health, setHealth] = useState<Health | null>(null);
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [serverForm, setServerForm] = useState<Server | 'new' | null>(null);
  const [serviceForm, setServiceForm] = useState<Service | 'new' | null>(null);
  const [confirm, setConfirm] = useState<{ title: string; action: () => Promise<void> } | null>(
    null,
  );
  const serviceRequest = useRef(0);
  const current = servers.items.find((x) => x.id === selected);
  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) expired();
      else setError(message(err));
    },
    [expired],
  );
  const refresh = useCallback(async () => {
    setBusy(true);
    setError('');
    try {
      const [list, status] = await Promise.all([
        api<Page<Server>>(`/servers?offset=${serverOffset}`),
        api<Health>('/health'),
      ]);
      setServers(list);
      setHealth(status);
      setSelected((value) =>
        list.items.some((x) => x.id === value) ? value : (list.items[0]?.id ?? null),
      );
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }, [serverOffset, fail]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  useEffect(() => {
    setServiceOffset(0);
  }, [selected]);
  const refreshServices = useCallback(async () => {
    const requestId = ++serviceRequest.current;
    if (!selected) {
      setServices(EMPTY);
      return;
    }
    try {
      const result = await api<Page<Service>>(
        `/servers/${selected}/services?offset=${serviceOffset}`,
      );
      if (requestId === serviceRequest.current) setServices(result);
    } catch (err) {
      fail(err);
    }
  }, [selected, serviceOffset, fail]);
  useEffect(() => {
    setServices(EMPTY);
    void refreshServices();
  }, [refreshServices]);
  async function saveServer(body: unknown) {
    const result = await api<Server>(
      serverForm === 'new' ? '/servers' : `/servers/${(serverForm as Server).id}`,
      session.csrf_token,
      serverForm === 'new' ? 'POST' : 'PUT',
      body,
    );
    await refresh();
    setSelected(result.id);
    setNotice('Servidor guardado.');
  }
  async function saveService(body: unknown) {
    await api(
      serviceForm === 'new'
        ? `/servers/${selected}/services`
        : `/services/${(serviceForm as Service).id}`,
      session.csrf_token,
      serviceForm === 'new' ? 'POST' : 'PUT',
      body,
    );
    await refreshServices();
    setNotice('Servicio guardado. El recolector está pendiente de implementación.');
  }
  async function changeService(service: Service, changes: Partial<Service>) {
    await api(`/services/${service.id}`, session.csrf_token, 'PUT', {
      name: service.name,
      url: service.url,
      interval_seconds: service.interval_seconds,
      options: service.options,
      enabled: service.enabled,
      archived: service.archived,
      ...changes,
    });
    await refreshServices();
  }
  async function archiveServer() {
    if (!current) return;
    await api(`/servers/${current.id}`, session.csrf_token, 'PUT', {
      name: current.name,
      description: current.description,
      tags: current.tags,
      archived: !current.archived,
    });
    await refresh();
    await refreshServices();
  }
  async function logout(all = false) {
    try {
      await api(all ? '/auth/revoke-sessions' : '/auth/logout', session.csrf_token, 'POST');
      expired();
    } catch (err) {
      fail(err);
    }
  }
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">
          ESPACIO DE TRABAJO <span>Personal</span>
        </div>
        <div className="nav-current">
          <Layers3 size={18} />
          Infraestructura<span>{servers.total}</span>
        </div>
        <div className="sidebar-section">
          <span>TUS SERVIDORES</span>
          <button
            className="icon-button"
            aria-label="Añadir servidor"
            onClick={() => setServerForm('new')}
          >
            <Plus size={16} />
          </button>
        </div>
        <nav aria-label="Servidores">
          {servers.items.map((server) => (
            <button
              key={server.id}
              className={`server-nav ${selected === server.id ? 'selected' : ''}`}
              onClick={() => setSelected(server.id)}
            >
              <ServerIcon size={16} />
              <span>{server.name}</span>
              {server.archived && <Archive size={14} />}
            </button>
          ))}
          {!servers.items.length && (
            <p className="sidebar-hint">Tu infraestructura empieza con un servidor.</p>
          )}
        </nav>
        {servers.total > 50 && (
          <div className="pagination">
            <button
              aria-label="Servidores anteriores"
              disabled={!serverOffset}
              onClick={() => setServerOffset((x) => x - 50)}
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              {serverOffset + 1}–{Math.min(serverOffset + 50, servers.total)}
            </span>
            <button
              aria-label="Servidores siguientes"
              disabled={serverOffset + 50 >= servers.total}
              onClick={() => setServerOffset((x) => x + 50)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        )}
        <div className="sidebar-bottom">
          <div className="foundation-badge">
            <span className="dot" /> Apache · Histórico
          </div>
          <div className="account">
            <div className="avatar">A</div>
            <div>
              <strong>Administrador</strong>
              <span title={session.email}>{session.email}</span>
            </div>
            <button
              className="icon-button"
              aria-label="Cerrar sesión"
              onClick={() => void logout()}
            >
              <LogOut size={17} />
            </button>
          </div>
          <button
            className="revoke-link"
            onClick={() =>
              setConfirm({
                title: 'Cerrar todas las sesiones de tu cuenta',
                action: () => logout(true),
              })
            }
          >
            Cerrar todas las sesiones
          </button>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <div>
            <span>Espacio personal</span>
            <ChevronRight size={14} />
            <strong>Infraestructura</strong>
          </div>
          <span className="private-label">
            <LockKeyhole size={13} />
            Acceso privado
          </span>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">CENTRO DE CONTROL</span>
              <h1>Tu infraestructura</h1>
              <p className="muted">Conecta tus servidores. Organiza lo que necesitas observar.</p>
            </div>
            <button className="primary" onClick={() => setServerForm('new')}>
              <Plus size={17} />
              Añadir servidor
            </button>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
          {notice && (
            <div className="notice" role="status">
              <Check size={16} />
              {notice}
              <button
                aria-label="Cerrar aviso"
                className="icon-button"
                onClick={() => setNotice('')}
              >
                <X size={16} />
              </button>
            </div>
          )}
          <section className="stats" aria-label="Resumen">
            <div className="stat">
              <span>
                Servidores registrados
                <ServerIcon size={18} />
              </span>
              <strong>{servers.total}</strong>
              <small>En este espacio de trabajo</small>
            </div>
            <div className="stat">
              <span>
                Servicios del servidor
                <Layers3 size={18} />
              </span>
              <strong>{services.total}</strong>
              <small>{current?.name ?? 'Selecciona o añade un servidor'}</small>
            </div>
            <div className="stat">
              <span>
                Almacenamiento
                <Database size={18} />
              </span>
              <strong className="status-value">
                {health?.database === 'ok' ? 'Conectado' : 'Sin verificar'}
              </strong>
              <small>Configuración persistente en PostgreSQL</small>
            </div>
          </section>
          <section className="foundation-note">
            <div className="square-icon">
              <Radio size={20} />
            </div>
            <div>
              <strong>Observa la actividad de Apache.</strong>
              <p>
                Ya puedes organizar servidores y servicios. Apache Status ya dispone de recogida
                periódica e histórico. Abre «Ver diagnóstico» para consultar las muestras. MRTG
                sigue pendiente de recolector.
              </p>
            </div>
            <span className="tag">DIAGNÓSTICO APACHE</span>
          </section>
          <section className="service-panel">
            <div className="panel-heading">
              <div className="server-title">
                <span className="square-icon">
                  <ServerIcon size={21} />
                </span>
                <div>
                  <span className="eyebrow">SERVIDOR SELECCIONADO</span>
                  <h2>{current?.name ?? 'Añade tu primer servidor'}</h2>
                  {current?.description && <p className="muted small">{current.description}</p>}
                </div>
              </div>
              {current && (
                <div className="panel-actions">
                  <button
                    className="icon-button"
                    aria-label="Editar servidor"
                    onClick={() => setServerForm(current)}
                  >
                    <Pencil size={17} />
                  </button>
                  <button
                    className="icon-button"
                    aria-label={current.archived ? 'Restaurar servidor' : 'Archivar servidor'}
                    onClick={() =>
                      setConfirm({
                        title: current.archived
                          ? 'Restaurar este servidor'
                          : 'Archivar este servidor y pausar sus servicios',
                        action: archiveServer,
                      })
                    }
                  >
                    <Archive size={17} />
                  </button>
                </div>
              )}
            </div>
            {!!current?.tags.length && (
              <div className="tags">
                {current.tags.map((tag) => (
                  <span className="tag" key={tag}>
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {current?.archived && (
              <div className="info-note">
                Servidor archivado. Su configuración se conserva y sus servicios no se ejecutarán.
              </div>
            )}
            <div className="toolbar">
              <label className="search">
                <Search size={17} />
                <input
                  aria-label="Buscar en los servicios de esta página"
                  placeholder="Buscar en esta página…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </label>
              <div>
                <button
                  className="icon-button"
                  aria-label="Actualizar"
                  disabled={busy}
                  onClick={() => {
                    void refresh();
                    void refreshServices();
                  }}
                >
                  <RefreshCw size={17} />
                </button>
                <button
                  className="secondary"
                  disabled={!current || current.archived}
                  onClick={() => setServiceForm('new')}
                >
                  <Plus size={16} />
                  Añadir servicio
                </button>
              </div>
            </div>
            {!services.items.length ? (
              <div className="empty-state">
                <span className="empty-icon">
                  <Layers3 size={30} />
                </span>
                <h3>
                  {busy
                    ? 'Cargando infraestructura…'
                    : current
                      ? 'Cada servicio cuenta una parte de la historia'
                      : 'Un punto de partida para todos tus servidores'}
                </h3>
                <p>
                  {current
                    ? 'Añade Apache Status para observar la actividad web o MRTG para seguir las estadísticas del sistema.'
                    : 'Crea un servidor y después elige qué servicios quieres monitorizar.'}
                </p>
                {!busy && (
                  <button
                    className="text-button"
                    disabled={current?.archived}
                    onClick={() => (current ? setServiceForm('new') : setServerForm('new'))}
                  >
                    {current ? 'Configurar primer servicio' : 'Crear primer servidor'}
                    <ArrowRight size={17} />
                  </button>
                )}
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Servicio / endpoint</th>
                      <th>Tipo</th>
                      <th>Intervalo</th>
                      <th>Estado</th>
                      <th>
                        <span className="sr-only">Acciones</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {services.items
                      .filter((x) =>
                        `${x.name} ${x.url}`.toLowerCase().includes(search.toLowerCase()),
                      )
                      .map((service) => (
                        <tr key={service.id}>
                          <td>
                            <div className="service-name">
                              <span className={`service-icon ${service.kind}`}>
                                <Globe2 size={18} />
                              </span>
                              <div>
                                <strong>{service.name}</strong>
                                {service.kind === 'apache_status' && (
                                  <button
                                    className="secondary"
                                    onClick={() => setDiagnostic(service)}
                                  >
                                    Ver diagnóstico
                                  </button>
                                )}
                                <span className="endpoint" title={service.url}>
                                  {service.url}
                                </span>
                                <small className="revision">
                                  Revisión {service.revision}
                                  {service.has_credentials ? ' · Credenciales guardadas' : ''}
                                </small>
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className="type-label">{KIND[service.kind]}</span>
                          </td>
                          <td>
                            <span className="interval">
                              <Clock3 size={13} />
                              {service.interval_seconds / 60} min
                            </span>
                          </td>
                          <td>
                            <span className={`status ${service.status}`}>
                              <span className="dot" />
                              {STATUS[service.status]}
                            </span>
                          </td>
                          <td>
                            <details className="row-menu">
                              <summary aria-label={`Acciones de ${service.name}`}>
                                <MoreHorizontal size={20} />
                              </summary>
                              <div>
                                <button onClick={() => setServiceForm(service)}>
                                  Editar servicio
                                </button>
                                <button
                                  disabled={service.archived || current?.archived}
                                  onClick={() =>
                                    changeService(service, { enabled: !service.enabled }).catch(
                                      fail,
                                    )
                                  }
                                >
                                  {service.enabled ? 'Pausar' : 'Habilitar'}
                                </button>
                                <button
                                  onClick={() =>
                                    setConfirm({
                                      title: service.archived
                                        ? 'Restaurar este servicio'
                                        : 'Archivar este servicio',
                                      action: () =>
                                        changeService(service, { archived: !service.archived }),
                                    })
                                  }
                                >
                                  {service.archived ? 'Restaurar' : 'Archivar'}
                                </button>
                              </div>
                            </details>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
                {search &&
                  !services.items.some((x) =>
                    `${x.name} ${x.url}`.toLowerCase().includes(search.toLowerCase()),
                  ) && <p className="no-results">No hay servicios que coincidan en esta página.</p>}
              </div>
            )}
            <div className="panel-footer">
              <span>
                <ShieldCheck size={14} /> Solo destinos autorizados
              </span>
              <div className="pagination">
                <button
                  aria-label="Servicios anteriores"
                  disabled={!serviceOffset}
                  onClick={() => setServiceOffset((x) => x - 50)}
                >
                  <ChevronLeft size={16} />
                </button>
                <span>
                  {services.total
                    ? `${serviceOffset + 1}–${Math.min(serviceOffset + 50, services.total)} de ${services.total}`
                    : '0 servicios'}
                </span>
                <button
                  aria-label="Servicios siguientes"
                  disabled={serviceOffset + 50 >= services.total}
                  onClick={() => setServiceOffset((x) => x + 50)}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </section>
          <footer className="content-footer">
            <span>
              Apache Status Monitor <span className="footer-separator">/</span> Open source, bajo tu
              control.
            </span>
            <span className={`scheduler-state ${health?.scheduler === 'ok' ? 'ok' : ''}`}>
              <span className="dot" />
              Planificador {health?.scheduler === 'ok' ? 'disponible' : 'sin señal reciente'}
            </span>
          </footer>
        </main>
      </div>
      {diagnostic && (
        <Dialog title={`Diagnóstico · ${diagnostic.name}`} close={() => setDiagnostic(null)}>
          <ApacheDiagnostics serviceId={diagnostic.id} />
        </Dialog>
      )}
      {serverForm && (
        <ServerForm
          current={serverForm === 'new' ? undefined : serverForm}
          close={() => setServerForm(null)}
          save={saveServer}
        />
      )}
      {serviceForm && (
        <ServiceForm
          current={serviceForm === 'new' ? undefined : serviceForm}
          close={() => setServiceForm(null)}
          save={saveService}
        />
      )}
      {confirm && (
        <Dialog title={confirm.title} close={() => setConfirm(null)}>
          <p className="muted">La configuración y el histórico se conservan.</p>
          <div className="form-actions">
            <button className="secondary" onClick={() => setConfirm(null)}>
              Cancelar
            </button>
            <button
              className="primary"
              onClick={() => {
                const action = confirm.action;
                setConfirm(null);
                void action().catch(fail);
              }}
            >
              Confirmar
            </button>
          </div>
        </Dialog>
      )}
    </div>
  );
}

function App() {
  const [setup, setSetup] = useState(false);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const expired = useCallback(() => setSession(null), []);
  useEffect(() => {
    api<Session>('/auth/session')
      .then(setSession)
      .catch(async (err) => {
        if (err instanceof ApiError && err.status === 401) {
          try {
            const status = await api<{ available: boolean }>('/setup/status');
            setSetup(status.available);
          } catch (setupError) {
            setError(message(setupError));
          }
        } else setError(message(err));
      })
      .finally(() => setLoading(false));
  }, []);
  if (loading)
    return (
      <div className="app-loading">
        <Activity size={30} />
        <span>Preparando tu espacio…</span>
      </div>
    );
  if (setup) return <Setup done={() => setSetup(false)} />;
  return session ? (
    <Workspace session={session} expired={expired} />
  ) : (
    <Login ready={setSession} initialError={error} />
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
