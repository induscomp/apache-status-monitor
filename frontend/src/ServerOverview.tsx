import { useEffect, useState } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts';
import { api } from './api';
import './overview.css';

type Resource = {
  value: number;
  unit: string;
  provenance: string;
  observed_at: string;
  source_at: string | null;
};
type Rankings = {
  ips?: {
    ip: string;
    count: number;
    country: string | null;
    asn: number | null;
    organization: string | null;
  }[];
  urls?: { domain: string; method: string; path: string; count: number }[];
  posts?: { domain: string; ip: string; path: string; count: number }[];
};
type Overview = {
  state: string;
  service_id: string | null;
  services: { id: string; name: string }[];
  last_at: string | null;
  learning: { valid_baseline_samples: number; required_samples: number };
  series: Record<string, number | string | null>[];
  metrics: Record<string, number | null>;
  resources: Record<string, Resource>;
  domains: { domain: string; active: number; appearances: number }[];
  period_rankings: { domain: string; appearances: number }[];
  rankings: Rankings;
  warnings: string[];
  open_incidents: number;
  limitation: string;
  geoip: { country: boolean; asn: boolean };
};
type Incident = {
  id: string;
  subject: string;
  status: string;
  severity: string;
  opened_at: string;
  updated_at: string;
  evidence: {
    value: number;
    reference: { median: number; mad: number; samples: number };
    note: string;
    feature: string;
    resources: Record<string, Resource>;
    domains?: { domain: string; active: number }[];
    coincidences: Rankings;
  };
};
const labels: Record<string, string> = {
  ram_free: 'RAM física libre',
  swap_free: 'Swap libre',
  cpu: 'CPU',
  load: 'Carga',
  processes: 'Procesos',
  tcp_connections: 'Conexiones TCP',
  http_processes: 'Procesos HTTP',
};
const states: Record<string, string> = {
  learning: 'Aprendiendo el comportamiento habitual',
  insufficient: 'Datos insuficientes o incompletos',
  resource_pressure: 'Presión de recursos detectada',
  anomaly: 'Actividad inusual detectada',
  observing: 'Sin anomalías detectadas en las muestras',
};
const number = (value: number | null | undefined) =>
  value == null
    ? 'Sin dato'
    : new Intl.NumberFormat('es', {
        maximumFractionDigits: 2,
        notation: Math.abs(value) >= 1e6 ? 'compact' : 'standard',
      }).format(value);
const date = (value: string | null) =>
  value ? new Date(value).toLocaleString('es') : 'Sin recogidas';

function Chart({
  title,
  data,
  lines,
}: {
  title: string;
  data: Overview['series'];
  lines: [string, string][];
}) {
  return (
    <section className="overview-card">
      <h3>{title}</h3>
      {data.length ? (
        <div className="history-chart">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                dataKey="at"
                minTickGap={50}
                tickFormatter={(v) =>
                  new Date(v).toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' })
                }
              />
              <YAxis width={65} tickFormatter={number} />
              <Tooltip labelFormatter={(v) => date(String(v))} />
              <Legend />
              {lines.map(([key, label], index) => (
                <Line
                  key={key}
                  dataKey={key}
                  name={label}
                  stroke={['#167361', '#b85b2b', '#416ab1'][index % 3]}
                  dot={false}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <p>Esperando muestras.</p>
      )}
    </section>
  );
}
function ResourceCards({ values }: { values: Record<string, Resource> }) {
  return (
    <div className="resource-grid">
      {Object.entries(labels).map(([key, label]) => (
        <div className="overview-card" key={key}>
          <h3>{label}</h3>
          <strong className="metric-number">{number(values[key]?.value)}</strong>
          <p>{values[key]?.unit || 'Sin lectura correlacionable'}</p>
          {values[key] && (
            <details>
              <summary>Fuente y fecha</summary>
              <p>{values[key].provenance}</p>
              <p>Recogida: {date(values[key].observed_at)}</p>
              <p>
                Fuente:{' '}
                {values[key].source_at ? date(values[key].source_at) : 'Zona horaria sin verificar'}
              </p>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}
function Evidence({ rankings }: { rankings: Rankings }) {
  return (
    <div className="overview-grid">
      <section className="overview-card">
        <h3>IPs con más conexiones observadas</h3>
        <div className="overview-table">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Workers activos</th>
                <th>País / ASN</th>
              </tr>
            </thead>
            <tbody>
              {rankings.ips?.map((r) => (
                <tr key={r.ip}>
                  <td>{r.ip}</td>
                  <td>{r.count}</td>
                  <td>
                    {r.country || 'Desconocido'} /{' '}
                    {r.asn ? `AS${r.asn} ${r.organization || ''}` : 'Desconocido'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="overview-card">
        <h3>URLs más repetidas en la muestra</h3>
        <div className="overview-table">
          <table>
            <thead>
              <tr>
                <th>Dominio / petición</th>
                <th>Apariciones</th>
              </tr>
            </thead>
            <tbody>
              {rankings.urls?.map((r, i) => (
                <tr key={i}>
                  <td>
                    {r.domain}
                    <br />
                    {r.method} {r.path}
                  </td>
                  <td>{r.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="overview-card">
        <h3>POST a rutas sensibles</h3>
        <p>
          Patrones para revisar; también pueden ser peticiones legítimas. Incluye últimas peticiones
          de workers idle.
        </p>
        {!rankings.posts?.length && <p>No observados en esta muestra.</p>}
        <div className="overview-table">
          <table>
            <tbody>
              {rankings.posts?.map((r, i) => (
                <tr key={i}>
                  <td>
                    {r.domain}
                    <br />
                    {r.ip}
                    <br />
                    POST {r.path}
                  </td>
                  <td>{r.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
export function ServerOverview({
  serverId,
  view,
}: {
  serverId: string;
  view: 'status' | 'incidents';
}) {
  const [data, setData] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [service, setService] = useState('');
  const [domain, setDomain] = useState('');
  const [error, setError] = useState('');
  const [offset, setOffset] = useState(0);
  const [moreCharts, setMoreCharts] = useState(false);
  useEffect(() => {
    setService('');
    setDomain('');
    setData(null);
    setOffset(0);
    setIncidents([]);
  }, [serverId]);
  useEffect(() => {
    let live = true;
    const refresh = async () => {
      try {
        const query = new URLSearchParams({
          hours: '24',
          ...(service ? { service_id: service } : {}),
          ...(domain ? { domain } : {}),
        });
        const [overview, incidentPage] = await Promise.all([
          api<Overview>(`/servers/${serverId}/analysis?${query}`),
          api<{ items: Incident[] }>(`/servers/${serverId}/incidents?offset=${offset}`),
        ]);
        if (live) {
          setData(overview);
          setIncidents(incidentPage.items);
          setError('');
        }
      } catch (e) {
        if (live) setError((e as Error).message);
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 30000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [serverId, service, domain, offset]);
  return (
    <div className="server-overview">
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!data ? (
        <p>Cargando estado…</p>
      ) : (
        <>
          <div className={`overview-status ${data.state}`}>
            <h2>{states[data.state]}</h2>
            <p>
              Última muestra: {date(data.last_at)} · {data.open_incidents} incidentes abiertos
            </p>
            <p>{data.limitation}</p>
            <p>
              Referencia del dominio: {data.learning.valid_baseline_samples}/
              {data.learning.required_samples} muestras válidas mínimas en 24 h; se excluyen los
              últimos 30 minutos.
            </p>
          </div>
          {view === 'incidents' ? (
            <>
              <h2>Incidentes</h2>
              <p>
                Coincidencias entre Apache y MRTG. La ausencia de datos no resuelve un incidente.
              </p>
              {!incidents.length && <p>No hay incidentes en esta página.</p>}
              {incidents.map((i) => (
                <article className="overview-card" key={i.id}>
                  <h3>
                    {i.subject.replace('domain:', 'Dominio: ').replace('resource:', 'Recurso: ')} ·{' '}
                    {i.status === 'open' ? 'Abierto' : 'Resuelto'} ·{' '}
                    {i.severity === 'critical' ? 'Prioridad alta' : 'Prioridad media'}
                  </h3>
                  <p>
                    Inicio: {date(i.opened_at)} · Actualizado: {date(i.updated_at)}
                  </p>
                  <p>
                    {i.evidence.feature}: {number(i.evidence.value)}; mediana habitual{' '}
                    {number(i.evidence.reference?.median)} ({i.evidence.reference?.samples}{' '}
                    muestras).
                  </p>
                  <p>{i.evidence.note}</p>
                  <details>
                    <summary>Ver evidencias coincidentes</summary>
                    <ResourceCards values={i.evidence.resources || {}} />
                    {i.evidence.domains?.map((d) => (
                      <p key={d.domain}>
                        {d.domain}: {d.active} workers activos observados
                      </p>
                    ))}
                    <Evidence rankings={i.evidence.coincidences || {}} />
                  </details>
                </article>
              ))}
              <div className="overview-controls">
                <button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>
                  Anteriores
                </button>
                <button disabled={incidents.length < 50} onClick={() => setOffset(offset + 50)}>
                  Siguientes
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="overview-controls">
                <label>
                  Servicio Apache
                  <select
                    value={service || data.service_id || ''}
                    onChange={(e) => {
                      setService(e.target.value);
                      setDomain('');
                    }}
                  >
                    {data.services.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </label>
                <span>Últimas 24 horas · recogida cada 5 minutos</span>
              </div>
              {data.warnings.length > 0 && (
                <details className="overview-card">
                  <summary>Calidad y cobertura ({data.warnings.length} avisos)</summary>
                  {data.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                </details>
              )}
              <ResourceCards values={data.resources} />
              <div className="resource-grid">
                {[
                  ['active_connections', 'Workers con conexión observada'],
                  ['active_requests', 'Requests activas R/W'],
                  ['idle_workers', 'Workers idle'],
                  ['free_slots', 'Slots libres'],
                  ['req_per_sec', 'Req/s entre muestras'],
                  ['bytes_per_sec', 'Bytes/s entre muestras'],
                  ['request_ms', 'Media ms/request entre muestras'],
                ].map(([key, label]) => (
                  <section className="overview-card" key={key}>
                    <h3>{label}</h3>
                    <strong className="metric-number">{number(data.metrics[key])}</strong>
                  </section>
                ))}
              </div>
              <div className="overview-grid">
                <Chart
                  title="Apache: actividad observada"
                  data={data.series}
                  lines={[
                    ['active_connections', 'Workers con conexión'],
                    ['active_requests', 'Requests R/W'],
                  ]}
                />
                {['ram_free', 'swap_free', 'load'].map((key) => (
                  <Chart
                    key={key}
                    title={`${labels[key]} · ${data.resources[key]?.unit || 'unidad de origen'}`}
                    data={data.series}
                    lines={[[key, labels[key]]]}
                  />
                ))}
              </div>
              <details
                className="overview-card"
                onToggle={(e) => setMoreCharts(e.currentTarget.open)}
              >
                <summary>
                  Más gráficos: CPU, procesos, conexiones TCP, tasas y tiempos Apache
                </summary>
                {moreCharts && (
                  <div className="overview-grid">
                    <Chart
                      title="Workers idle y slots libres"
                      data={data.series}
                      lines={[
                        ['idle_workers', 'Idle'],
                        ['free_slots', 'Slots libres'],
                      ]}
                    />
                    <Chart
                      title="Peticiones por segundo entre muestras"
                      data={data.series}
                      lines={[['req_per_sec', 'Req/s']]}
                    />
                    <Chart
                      title="Tráfico entre muestras (bytes/s)"
                      data={data.series}
                      lines={[['bytes_per_sec', 'Bytes/s']]}
                    />
                    <Chart
                      title="Tiempo medio por request entre muestras (ms)"
                      data={data.series}
                      lines={[['request_ms', 'ms/request']]}
                    />
                    {['cpu', 'processes', 'tcp_connections', 'http_processes'].map((key) => (
                      <Chart
                        key={key}
                        title={`${labels[key]} · ${data.resources[key]?.unit || 'unidad de origen'}`}
                        data={data.series}
                        lines={[[key, labels[key]]]}
                      />
                    ))}
                  </div>
                )}
              </details>
              <h2>Dominios</h2>
              <p>
                Un worker puede conservar su última petición. Las apariciones acumuladas son
                presencia en muestras, no visitas ni tráfico total. Los históricos están separados
                por servicio.
              </p>
              <div className="overview-grid">
                <section className="overview-card">
                  <h3>Más conexiones activas ahora</h3>
                  <div className="overview-table">
                    <table>
                      <thead>
                        <tr>
                          <th>Dominio</th>
                          <th>Workers activos</th>
                          <th>Apariciones actuales</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.domains.map((d) => (
                          <tr key={d.domain}>
                            <td>
                              <button onClick={() => setDomain(d.domain)}>{d.domain}</button>
                            </td>
                            <td>{d.active}</td>
                            <td>{d.appearances}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
                <section className="overview-card">
                  <h3>Más apariciones en 24 horas</h3>
                  <div className="overview-table">
                    <table>
                      <tbody>
                        {data.period_rankings.map((d) => (
                          <tr key={d.domain}>
                            <td>
                              <button onClick={() => setDomain(d.domain)}>{d.domain}</button>
                            </td>
                            <td>{d.appearances}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              </div>
              {domain && (
                <Chart
                  title={`Histórico de ${domain}`}
                  data={data.series}
                  lines={[
                    ['domain_active', 'Workers activos'],
                    ['domain_appearances', 'Apariciones'],
                  ]}
                />
              )}
              {(!data.geoip.country || !data.geoip.asn) && (
                <p>
                  GeoIP local incompleto: instala las bases Country y ASN en la carpeta geoip para
                  enriquecer las IPs. No se realizan consultas externas.
                </p>
              )}
              <Evidence rankings={data.rankings} />
            </>
          )}
        </>
      )}
    </div>
  );
}

type Mail = {
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  sender: string;
  recipient: string;
  password?: string;
  has_password?: boolean;
  deliveries?: { status: string; transition: string; created_at: string; error: string | null }[];
};
export function MailConfiguration({ csrf }: { csrf: string }) {
  const [form, setForm] = useState<Mail>({
    enabled: false,
    host: '',
    port: 465,
    username: '',
    sender: '',
    recipient: '',
  });
  const [message, setMessage] = useState('');
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let live = true;
    void api<Mail>('/notifications')
      .then((v) => {
        if (live) {
          setForm((f) => ({ ...f, ...v }));
          setReady(true);
        }
      })
      .catch((e) => {
        if (live) setMessage(e.message);
      });
    return () => {
      live = false;
    };
  }, []);
  return (
    <section className="overview-card">
      <h2>Correo de incidentes</h2>
      <p>
        SMTP con TLS directo y certificado verificado (habitualmente puerto 465). Dos muestras
        anómalas abren el incidente; tres recuperadas lo resuelven. Recordatorios como máximo cada
        hora.
      </p>
      <form
        className="mail-form"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api('/notifications', csrf, 'PUT', {
              enabled: form.enabled,
              host: form.host,
              port: form.port,
              username: form.username,
              sender: form.sender,
              recipient: form.recipient,
              password: form.password || null,
            });
            setForm((f) => ({ ...f, password: '' }));
            setMessage(
              'Configuración guardada. Los próximos incidentes utilizarán este canal si está activado.',
            );
          } catch (e) {
            setMessage((e as Error).message);
          }
        }}
      >
        <label>
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />{' '}
          Activar avisos por email
        </label>
        {(['host', 'username', 'sender', 'recipient'] as const).map((key) => (
          <label key={key}>
            {
              {
                host: 'Servidor SMTP',
                username: 'Usuario SMTP',
                sender: 'Remitente',
                recipient: 'Destinatario',
              }[key]
            }
            <input
              type={key === 'sender' || key === 'recipient' ? 'email' : 'text'}
              value={form[key]}
              onChange={(e) => setForm({ ...form, [key]: e.target.value })}
            />
          </label>
        ))}
        <label>
          Puerto TLS
          <input
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
          />
        </label>
        <label>
          Contraseña SMTP
          <input
            type="password"
            autoComplete="new-password"
            value={form.password || ''}
            placeholder={form.has_password ? 'Guardada; deja vacío para conservarla' : ''}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
        </label>
        <button className="primary" disabled={!ready}>
          Guardar correo
        </button>
      </form>
      {message && <p role="status">{message}</p>}
      <h3>Últimas entregas</h3>
      {form.deliveries?.length ? (
        form.deliveries.map((d, i) => (
          <p key={i}>
            {date(d.created_at)} · {d.transition} · {d.status} {d.error}
          </p>
        ))
      ) : (
        <p>Aún no hay envíos registrados.</p>
      )}
    </section>
  );
}
