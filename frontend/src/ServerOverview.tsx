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
import { memory, numeric, subjectText, incidentExplanation } from './incidentText';
import './overview.css';
import { IncidentTimeline } from './IncidentTimeline';
import type { IncidentSummary } from './IncidentTimeline';
import { SourceList } from './Dashboard';
import type { Source } from './Dashboard';

type Resource = {
  value: number;
  display_bytes?: number;
  display_factor?: number;
  display_note?: string;
  unit: string;
  provenance: string;
  observed_at: string;
  source_at: string | null;
};
type Rankings = {
  scope?: string;
  ips?: {
    ip: string;
    count: number;
    country: string | null;
    asn: number | null;
    organization: string | null;
    network?: string | null;
    database_at?: string | null;
    source?: string;
  }[];
  urls?: { domain: string; method: string; path: string; count: number }[];
  posts?: { domain: string; ip: string; path: string; count: number }[];
};
type Overview = {
  sources?: Source[];
  open_subjects?: string[];
  priority?: string;
  has_apache?: boolean;
  backup?: { state: string; last_at: string | null };
  incident_summary?: IncidentSummary;
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
  progress?: {
    phase: string;
    recovery_samples: number;
    required_recovery_samples: number;
    last_evaluated_at: string | null;
  };
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
    swap_state?: string;
    severity_policy?: string;
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
  sources_only: 'Resumen de las fuentes disponibles',
  unconfigured: 'Configura las fuentes de este servidor',
  learning: 'Aprendiendo el comportamiento habitual',
  insufficient: 'Datos insuficientes o incompletos',
  resource_pressure: 'Recursos fuera de lo habitual',
  anomaly: 'Actividad inusual detectada',
  observing: 'Sin anomalías detectadas en las muestras',
};
const number = numeric;
const date = (value: string | null) =>
  value ? new Date(value).toLocaleString('es') : 'Sin recogidas';

function Chart({
  title,
  data,
  lines,
  bytes = false,
}: {
  title: string;
  data: Overview['series'];
  lines: [string, string][];
  bytes?: boolean;
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
              <YAxis width={65} tickFormatter={bytes ? memory : number} />
              <Tooltip
                labelFormatter={(v) => date(String(v))}
                formatter={(value) => (bytes ? memory(Number(value)) : number(Number(value)))}
              />
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
          <strong className="metric-number">
            {values[key]?.display_bytes != null
              ? memory(values[key].display_bytes!)
              : number(values[key]?.value)}
          </strong>
          <p>
            {values[key]?.display_bytes != null
              ? 'Memoria disponible según MRTG'
              : values[key]?.unit === 'valor de origen'
                ? 'Unidad pendiente de confirmar'
                : values[key]?.unit || 'Sin lectura correlacionable'}
          </p>
          {values[key] && (
            <details>
              <summary>Fuente y fecha</summary>
              <p>{values[key].provenance}</p>
              <p>{values[key].display_note}</p>
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
  const providers = new Map<string, { name: string; count: number; ips: number }>();
  for (const row of rankings.ips || []) {
    const key = row.asn ? `AS${row.asn}` : 'unknown';
    const provider = providers.get(key) || {
      name: row.asn
        ? `${row.organization || 'Organización desconocida'} · AS${row.asn}`
        : 'Proveedor sin identificar',
      count: 0,
      ips: 0,
    };
    provider.count += row.count;
    provider.ips += 1;
    providers.set(key, provider);
  }
  return (
    <div className="overview-grid">
      <section className="overview-card">
        <h3>Redes y proveedores observados</h3>
        <p>
          {rankings.scope === 'domain'
            ? 'Solo IPs con conexiones activas al dominio de este aviso.'
            : rankings.scope === 'unavailable'
              ? 'No se conserva una muestra que permita atribuir IPs a este dominio. No mostramos IPs de otros dominios como si fueran suyas.'
              : 'Conexiones activas del conjunto del servidor en esta muestra.'}
        </p>
        {[...providers.values()]
          .sort((a, b) => b.count - a.count)
          .map((p) => (
            <p key={p.name}>
              <strong>{p.name}</strong>: {p.count} conexiones observadas desde {p.ips} IPs.
            </p>
          ))}
        {!providers.size && <p>Sin IPs activas atribuibles en esta evidencia.</p>}
        <p>
          Resumen de las IPs mostradas (máximo 30). El ASN identifica la red: puede pertenecer a un
          cloud, operador o empresa. No identifica a una persona ni demuestra un ataque.
        </p>
        <p>
          Consulta local, sin enviar IPs de visitantes.{' '}
          <a href="https://db-ip.com" target="_blank" rel="noreferrer">
            IP Geolocation by DB-IP
          </a>{' '}
          (Lite, CC BY 4.0); GeoLite2 cuando está disponible. La clasificación corresponde a la base
          actual, no necesariamente al propietario histórico.
        </p>
      </section>
      <section className="overview-card">
        <h3>IPs con más conexiones observadas</h3>
        <div className="overview-table">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Workers activos</th>
                <th>País / proveedor / rango</th>
              </tr>
            </thead>
            <tbody>
              {rankings.ips?.map((r) => (
                <tr key={r.ip}>
                  <td>{r.ip}</td>
                  <td>{r.count}</td>
                  <td>
                    {r.country
                      ? new Intl.DisplayNames(['es'], { type: 'region' }).of(r.country) || r.country
                      : 'País desconocido'}
                    <br />
                    {r.asn
                      ? `AS${r.asn} · ${r.organization || 'Organización desconocida'}`
                      : 'Proveedor desconocido'}
                    <div>
                      {r.network ? `Rango de la base IP: ${r.network}` : 'Rango no disponible'}
                    </div>
                    {r.database_at && <small>Base actualizada: {date(r.database_at)}</small>}
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
  openIncidents,
  detailMode = false,
  showCharts,
  configure,
  openSource,
}: {
  serverId: string;
  view: 'status' | 'incidents';
  openIncidents: () => void;
  detailMode?: boolean;
  showCharts: () => void;
  configure: () => void;
  openSource: (id: string) => void;
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
          {view === 'status' && data.incident_summary && (
            <IncidentTimeline
              summary={data.incident_summary}
              openIncidents={openIncidents}
              showCharts={showCharts}
              configure={configure}
            />
          )}
          <div className={`overview-status ${data.state} ${data.priority || ''}`}>
            <h2>{states[data.state]}</h2>
            <p>
              Última muestra: {date(data.last_at)} · {data.open_incidents} incidentes abiertos
            </p>
            <p>
              {data.open_subjects?.length
                ? `Revisar ahora: ${data.open_subjects.map(subjectText).join(' · ')}.`
                : 'Los avisos resueltos se conservan como histórico.'}{' '}
              Un aviso de recursos puede seguir abierto aunque un aviso de dominio ya se haya
              resuelto.
            </p>
            <details>
              <summary>Cómo interpretar este estado</summary>
              <p>{data.limitation}</p>
              {data.has_apache !== false && (
                <p>
                  Muestras disponibles para aprender el comportamiento:{' '}
                  {data.learning.valid_baseline_samples}. Mínimo requerido:
                  {data.learning.required_samples} muestras válidas mínimas en 24 h; se excluyen los
                  últimos 30 minutos.
                </p>
              )}
            </details>
          </div>
          {view === 'incidents' ? (
            <>
              <h2>Incidentes</h2>
              <p>
                Estos avisos señalan cambios que conviene revisar. La prioridad no mide la
                probabilidad de un ataque. Los avisos resueltos describen hechos pasados.
              </p>
              {!incidents.length && <p>No hay incidentes en esta página.</p>}
              {incidents.map((i) => (
                <article className="overview-card" key={i.id}>
                  <h3>
                    {subjectText(i.subject)} · {i.status === 'open' ? 'Abierto' : 'Resuelto'} ·{' '}
                    {i.severity === 'critical'
                      ? 'Prioridad de revisión alta'
                      : 'Prioridad de revisión media'}
                  </h3>
                  <p>
                    Inicio: {date(i.opened_at)} · Actualizado: {date(i.updated_at)}
                  </p>
                  <p>
                    {incidentExplanation(
                      i.subject,
                      i.evidence.feature,
                      i.evidence.value,
                      i.evidence.reference?.median,
                      i.evidence.resources?.[i.evidence.feature]?.display_factor,
                    )}
                  </p>
                  {i.progress && (
                    <p>
                      {i.progress.phase === 'recovering'
                        ? `Recuperación en curso: ${i.progress.recovery_samples}/${i.progress.required_recovery_samples} muestras válidas.`
                        : i.progress.phase === 'awaiting'
                          ? 'Esperando evidencia reciente y comparable; no se considera resuelto.'
                          : i.progress.phase === 'resolved'
                            ? 'Recuperación confirmada.'
                            : 'La última evaluación mantiene la anomalía.'}{' '}
                      Última evaluación: {date(i.progress.last_evaluated_at)}
                    </p>
                  )}
                  {i.evidence.severity_policy === 'memory-swap-v1' && (
                    <p>
                      {i.evidence.swap_state === 'used'
                        ? 'Rojo: hay uso de swap confirmado por su capacidad configurada.'
                        : i.evidence.swap_state === 'unused'
                          ? 'Naranja: aviso de memoria sin uso de swap.'
                          : i.severity === 'critical'
                            ? 'Se mantiene el rojo previo: faltan datos para confirmar que ha dejado de usarse swap.'
                            : 'Naranja: no podemos confirmar uso de swap. Configura su capacidad total y unidad en la métrica MRTG de swap libre.'}
                    </p>
                  )}
                  <p>
                    {i.subject.startsWith('domain:')
                      ? 'Se detectó actividad inusual, no un ataque confirmado. Puede corresponder a visitas, rastreadores o automatización. Revisa las IPs y las peticiones del dominio antes de atribuir una causa.'
                      : 'Este aviso compara recursos con su histórico. No confirma que se haya agotado la memoria ni que un dominio sea responsable.'}
                  </p>
                  <p>
                    {i.status === 'resolved'
                      ? 'La actividad volvió a su referencia durante las muestras válidas requeridas. El aviso se conserva como histórico.'
                      : 'Qué revisar: si el cambio persiste, qué dominios e IPs coinciden y si aumentan los POST a rutas sensibles.'}
                  </p>
                  <details>
                    <summary>Ver IPs, peticiones y recursos de ese momento</summary>
                    <p>
                      Lectura que activó o actualizó el aviso; no es la suma de toda su duración.
                      Recursos compartidos por todo el servidor.
                    </p>
                    <p>
                      Referencia calculada con {i.evidence.reference?.samples} muestras anteriores.
                      Mediana/MAD, excluyendo los últimos 30 minutos.
                    </p>
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
              {data.backup && (
                <p className="backup-state">
                  Backup cifrado:{' '}
                  {data.backup.state === 'ok'
                    ? `disponible · ${date(data.backup.last_at)}`
                    : 'sin copia reciente verificada'}
                </p>
              )}
              <div className="overview-controls">
                {data.has_apache !== false && (
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
                )}
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
              {(!detailMode || data.has_apache === false) && (
                <section className="overview-card">
                  <h2>Fuentes de este servidor</h2>
                  <p>Configura solo los sistemas disponibles en este servidor.</p>
                  <SourceList sources={data.sources || []} open={openSource} />
                  <div className="overview-controls">
                    <button className="secondary" onClick={configure}>
                      Configurar fuentes
                    </button>
                    <button className="primary" onClick={showCharts}>
                      Ampliar gráficos y rankings
                    </button>
                  </div>
                </section>
              )}
              {Object.keys(data.resources).length > 0 && <ResourceCards values={data.resources} />}
              {detailMode && data.has_apache === false && data.series.length > 0 && (
                <div className="overview-grid">
                  {Object.keys(labels)
                    .filter((key) => data.series.some((point) => point[key] != null))
                    .map((key) => (
                      <Chart
                        key={key}
                        title={`${labels[key]} · ${data.resources[key]?.display_bytes != null ? 'memoria disponible' : data.resources[key]?.unit || 'unidad de origen'}`}
                        bytes={data.resources[key]?.display_bytes != null}
                        data={data.series}
                        lines={[[key, labels[key]]]}
                      />
                    ))}
                </div>
              )}
              {detailMode && data.has_apache !== false && (
                <>
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
                        title={`${labels[key]} · ${data.resources[key]?.display_bytes != null ? 'memoria disponible' : data.resources[key]?.unit || 'unidad de origen'}`}
                        bytes={data.resources[key]?.display_bytes != null}
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
                            title={`${labels[key]} · ${data.resources[key]?.display_bytes != null ? 'memoria disponible' : data.resources[key]?.unit || 'unidad de origen'}`}
                            bytes={data.resources[key]?.display_bytes != null}
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
                    presencia en muestras, no visitas ni tráfico total. Los históricos están
                    separados por servicio.
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
                      Faltan bases locales de país o proveedor. Consulta la guía de redes para
                      instalar DB-IP Lite o GeoLite2. No se realizan consultas externas con las IPs.
                    </p>
                  )}
                  <Evidence rankings={data.rankings} />
                </>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

type Mail = {
  security?: 'tls' | 'starttls';
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  sender: string;
  recipient: string;
  password?: string;
  has_password?: boolean;
  verified_at?: string | null;
  last_error?: string | null;
  deliveries?: { status: string; transition: string; created_at: string; error: string | null }[];
};
export function MailConfiguration({ csrf, accountEmail }: { csrf: string; accountEmail: string }) {
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
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    let live = true;
    void api<Mail>('/notifications')
      .then((v) => {
        if (live) {
          setForm((f) => ({ ...f, ...v, recipient: v.recipient || accountEmail }));
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
      <h2>Correo de la cuenta</h2>
      <p>
        Configura el email de sistema que enviará las alertas de tus servidores y el destinatario
        que las recibirá. La dirección de acceso es independiente.
      </p>
      <p>
        SMTP con TLS directo o STARTTLS obligatorio y certificado verificado. Las muestras anómalas
        configuradas abren el incidente; las recuperadas configuradas lo resuelven. Recordatorios
        como máximo cada hora.
      </p>
      <form
        className="mail-form"
        onChange={(e) => {
          if (!(e.target instanceof HTMLInputElement && e.target.type === 'checkbox')) {
            setDirty(true);
            setForm((f) => ({ ...f, enabled: false, verified_at: null }));
          }
        }}
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            await api('/notifications', csrf, 'PUT', {
              security: form.security || 'tls',
              enabled: form.enabled,
              host: form.host,
              port: form.port,
              username: form.username,
              sender: form.sender,
              recipient: form.recipient,
              password: form.password || null,
            });
            setForm(await api<Mail>('/notifications'));
            setDirty(false);
            setMessage(
              form.enabled
                ? 'Avisos por correo activados.'
                : 'Configuración guardada. Comprueba el correo antes de activar los avisos.',
            );
          } catch (e) {
            setMessage((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <fieldset disabled={busy || !ready} style={{ border: 0, padding: 0, display: 'contents' }}>
          <label>
            <input
              type="checkbox"
              disabled={dirty || !form.verified_at}
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
                  sender: 'Email de sistema (remitente)',
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
            Seguridad SMTP
            <select
              value={form.security || 'tls'}
              onChange={(e) =>
                setForm({
                  ...form,
                  security: e.target.value as 'tls' | 'starttls',
                  port: e.target.value === 'tls' ? 465 : 587,
                })
              }
            >
              <option value="tls">TLS directo (465)</option>
              <option value="starttls">STARTTLS obligatorio (587)</option>
            </select>
          </label>
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
          <button className="primary" disabled={!ready || busy}>
            {busy ? 'Procesando…' : 'Guardar correo'}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!ready || busy || dirty}
            onClick={async () => {
              setBusy(true);
              setMessage('Comprobando conexión y enviando un correo de prueba…');
              try {
                const result = await api<{ ok: boolean; message: string }>(
                  '/notifications/test',
                  csrf,
                  'POST',
                  {},
                );
                setMessage(result.message);
                setForm(await api<Mail>('/notifications'));
              } catch (error) {
                setMessage((error as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            Comprobar y enviar prueba
          </button>
        </fieldset>
      </form>
      <p>
        1. Guarda los datos. 2. Envía una prueba y comprueba tu bandeja. 3. Activa los avisos y
        guarda. Máximo una prueba cada cinco minutos y tres por hora. Cualquier fallo de envío
        suspende el canal.
      </p>
      {form.last_error && <p role="alert">{form.last_error}</p>}
      {form.verified_at && (
        <p>
          Última comprobación correcta: {date(form.verified_at)}.{' '}
          {form.enabled ? 'Avisos activados.' : 'Avisos desactivados.'}
        </p>
      )}
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
