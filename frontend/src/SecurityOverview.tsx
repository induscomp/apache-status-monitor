import { useEffect, useState } from 'react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { api } from './api';
import { numeric, memory, resourceLabels } from './incidentText';

type Signal = {
  key: string;
  active: number;
  peak: number;
  score: number;
  category: string;
  reasons: string[];
  deviation: number | null;
  concentration: number;
  persistence: number;
  states: Record<string, number>;
  peers: Record<string, number>;
  req_mean: number | null;
  req_max: number | null;
  req_p95: number | null;
  geo?: { country: string | null; organization: string | null; asn: number | null };
};
type Assessment = {
  service_id: string;
  service: string;
  at: string;
  fresh: boolean;
  basis: string;
  samples: number;
  ips: Signal[];
  domains: Signal[];
  degradation: {
    metric: string;
    before: number;
    value: number;
    note: string;
    source: string;
    unit?: string;
  }[];
  contributors: { kind: string; key: string; reasons: string[] }[];
};
type Result = {
  state: string;
  items: Assessment[];
  series: { at: string; service: string; connections: number | null; anomalies: number | null }[];
  endpoints: { endpoint: string; observations: number }[];
  active_ips: {
    key: string;
    service: string;
    observations: number;
    peak: number;
    score: number;
    deviation: number | null;
    req_max: number | null;
  }[];
  active_domains: {
    key: string;
    service: string;
    observations: number;
    peak: number;
    score: number;
    deviation: number | null;
    req_max: number | null;
  }[];
};
const labels: Record<string, string> = {
  ...resourceLabels,
  request_ms: 'Tiempo medio entre muestras (ms)',
  busy_workers: 'Workers ocupados',
  idle_workers: 'Workers disponibles',
  free_slots: 'Slots libres',
  active_req_mean: 'Req medio (ms)',
  state_W: 'Estado W',
  state_R: 'Estado R',
  state_K: 'Estado K',
  state_C: 'Estado C',
};

export function SecurityOverview({
  serverId,
  service,
  hours,
}: {
  serverId: string;
  service: string;
  hours: number;
}) {
  const [data, setData] = useState<Result | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');
  const [ranking, setRanking] = useState<'observations' | 'score' | 'deviation' | 'req_max'>(
    'observations',
  );
  const [sort, setSort] = useState<'score' | 'active'>('score');
  useEffect(() => {
    let live = true;
    setData(null);
    const refresh = async () => {
      try {
        const result = await api<Result>(
          `/servers/${serverId}/security-analysis?hours=${hours}${service ? `&service_id=${service}` : ''}`,
        );
        if (live) {
          setData(result);
          setError('');
        }
      } catch (e) {
        if (live) setError((e as Error).message);
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 60000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [serverId, service, hours]);
  async function copy(ip: string) {
    try {
      await navigator.clipboard.writeText(ip);
      setCopied(`IP copiada: ${ip}`);
    } catch {
      setCopied(`No se pudo copiar. Selecciona la IP: ${ip}`);
    }
  }
  const table = (rows: Signal[], ip: boolean) => (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>{ip ? 'IP' : 'Dominio'}</th>
            <th>Ahora / pico 30 min</th>
            <th>Evaluación</th>
            <th>Evidencias</th>
          </tr>
        </thead>
        <tbody>
          {[...rows]
            .sort((a, b) => b[sort] - a[sort])
            .slice(0, 12)
            .map((r) => (
              <tr key={r.key}>
                <td>
                  {r.key}
                  {ip && (
                    <>
                      <br />
                      <small>
                        {r.geo?.country || 'País desconocido'} ·{' '}
                        {r.geo?.organization || 'Proveedor desconocido'}{' '}
                        {r.geo?.asn ? `AS${r.geo.asn}` : ''}
                      </small>
                      <br />
                      <button type="button" onClick={() => void copy(r.key)}>
                        Copiar IP
                      </button>
                    </>
                  )}
                </td>
                <td>
                  {r.active} / {r.peak}
                  <br />
                  <small>
                    {r.deviation == null
                      ? 'Sin multiplicador comparable'
                      : `×${numeric(r.deviation)} sobre su referencia`}
                  </small>
                </td>
                <td>
                  <span
                    className={`security-label ${r.category === 'posible ataque' ? 'danger' : r.score ? 'watch' : ''}`}
                  >
                    {r.category}
                  </span>
                  <br />
                  <small>Prioridad {r.score}/100 · no es probabilidad</small>
                </td>
                <td>
                  <details>
                    <summary>
                      {r.reasons.slice(2).join(' · ') || 'Sin señales combinadas; ver datos'}
                    </summary>
                    <ul>
                      {r.reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                    <p>
                      Concentración: {numeric(r.concentration * 100)} % en{' '}
                      {ip ? 'un dominio' : 'una IP'}. Estados:{' '}
                      {Object.entries(r.states)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(' · ')}
                      .
                    </p>
                    <p>
                      Req media / máximo / p95: {numeric(r.req_mean)} / {numeric(r.req_max)} /{' '}
                      {numeric(r.req_p95)} ms. p95 requiere 20 valores.
                    </p>
                    <p>
                      {Object.entries(r.peers)
                        .slice(0, 12)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(' · ')}
                    </p>
                  </details>
                </td>
              </tr>
            ))}
        </tbody>
      </table>
      {!rows.length && <p>Sin observaciones actuales suficientes.</p>}
    </div>
  );
  return (
    <section className="security-overview" aria-label="Seguridad y anomalías">
      <header>
        <h2>Seguridad y anomalías</h2>
        <strong>Estado general: {data?.state || 'Evaluando…'}</strong>
      </header>
      {error && <p role="alert">{error}</p>}
      <p className="monitor-footnote">
        Capturas cada 5 minutos, no visitas totales. Las señales orientan la revisión; no confirman
        ataques. El monitor no bloquea IP.
      </p>
      <p role="status">{copied}</p>
      {data && (
        <>
          <label>
            Ordenar señales{' '}
            <select value={sort} onChange={(e) => setSort(e.target.value as 'score' | 'active')}>
              <option value="score">Mayor anomalía</option>
              <option value="active">Mayor actividad</option>
            </select>
          </label>
          {data.items.map((item) => (
            <div key={item.service_id}>
              <h3>
                {item.service} · {item.fresh ? 'Lectura reciente' : 'Sin lectura reciente'}
              </h3>
              <small>
                Referencia: {item.basis || 'sin histórico comparable'} · {item.samples} muestras.
              </small>
              <details>
                <summary>
                  IPs sospechosas ahora · {item.ips.filter((r) => r.score > 0).length} con señales /{' '}
                  {item.ips.length} observadas
                </summary>
                {table(item.ips, true)}
              </details>
              <details>
                <summary>
                  Dominios bajo presión · {item.domains.filter((r) => r.score > 0).length} con
                  señales / {item.domains.length} observados
                </summary>
                {table(item.domains, false)}
              </details>
              <details open={item.degradation.length > 0}>
                <summary>
                  Salud y posibles responsables · {item.degradation.length} desviaciones
                </summary>
                {item.degradation.map((d) => (
                  <p key={d.metric}>
                    <strong>{labels[d.metric] || d.metric}</strong>:{' '}
                    {d.unit === 'bytes' ? memory(d.before) : numeric(d.before)} →{' '}
                    {d.unit === 'bytes' ? memory(d.value) : numeric(d.value)} · {d.source} ·{' '}
                    {d.note}
                  </p>
                ))}
                {!item.degradation.length && (
                  <p>
                    Sin degradación detectada en las señales comparables; los datos ausentes no
                    prueban salud.
                  </p>
                )}
                <h4>Posibles contribuyentes</h4>
                {item.contributors.map((c) => (
                  <p key={c.kind + c.key}>
                    <strong>{c.key}</strong> · coincide con: {c.reasons.join(' · ')}
                  </p>
                ))}
                <p>
                  Coincidencia temporal, no causa demostrada. Req no mide la latencia final del
                  navegador.
                </p>
              </details>
            </div>
          ))}
          <details>
            <summary>Gráficos y rankings · periodo seleccionado</summary>
            <p>
              El estado de arriba es actual. Estas gráficas y rankings cubren el periodo
              seleccionado. La suma cuenta observaciones, no peticiones distintas.
            </p>
            {data.items.map((item) => (
              <div key={item.service_id}>
                <h4>{item.service} · evolución de anomalías</h4>
                <div style={{ height: 190 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={data.series.filter((s) => s.service === item.service)}>
                      <XAxis
                        dataKey="at"
                        tickFormatter={(s) =>
                          new Date(s).toLocaleString('es', {
                            day: 'numeric',
                            month: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        }
                      />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Line
                        dataKey="anomalies"
                        name="Entidades con señales combinadas"
                        stroke="#cf7500"
                        dot={false}
                        connectNulls={false}
                      />
                      <Line
                        dataKey="connections"
                        name="Conexiones observadas"
                        stroke="#166b59"
                        dot={false}
                        connectNulls={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ))}
            <p>Los huecos indican muestras sin evaluación; no se reconstruyen alertas antiguas.</p>
            <label>
              Ordenar rankings del periodo{' '}
              <select
                value={ranking}
                onChange={(e) => setRanking(e.target.value as typeof ranking)}
              >
                <option value="observations">Actividad acumulada</option>
                <option value="score">Mayor anomalía evaluada</option>
                <option value="deviation">Mayor desviación histórica</option>
                <option value="req_max">Mayor tiempo Req</option>
              </select>
            </label>
            {(['active_ips', 'active_domains'] as const).map((group) => (
              <div key={group}>
                <h4>
                  {group === 'active_ips' ? 'IP más activas' : 'Dominios con mayor actividad'}
                </h4>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Entidad / servicio</th>
                        <th>Observaciones acumuladas</th>
                        <th>Pico</th>
                        <th>Prioridad máxima</th>
                        <th>Desviación máxima</th>
                        <th>Req máximo</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...data[group]]
                        .sort((a, b) => (b[ranking] || 0) - (a[ranking] || 0))
                        .slice(0, 12)
                        .map((r) => (
                          <tr key={r.service + r.key}>
                            <td>
                              {r.key} · {r.service}
                            </td>
                            <td>{r.observations}</td>
                            <td>{r.peak}</td>
                            <td>{r.score || 'Sin evaluación'}</td>
                            <td>
                              {r.deviation == null ? 'Sin referencia' : `×${numeric(r.deviation)}`}
                            </td>
                            <td>{numeric(r.req_max)} ms</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
            <h4>Endpoints sensibles más observados</h4>
            {data.endpoints.map((r) => (
              <p key={r.endpoint}>
                {r.endpoint} · {r.observations} observaciones
              </p>
            ))}
          </details>
          <p className="monitor-footnote">
            “Pico probablemente legítimo” significa actividad repartida sin rutas sensibles
            observadas, no una verificación de legitimidad. No se pueden deducir errores 404 ni
            continuidad de una conexión entre capturas.
          </p>
        </>
      )}
    </section>
  );
}
