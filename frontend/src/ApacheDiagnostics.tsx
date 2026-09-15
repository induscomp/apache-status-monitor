import { useEffect, useState } from 'react';
import { api } from './api';

type Sample = {
  id: string;
  observed_at: string;
  revision: number;
  status: string;
  metrics: { observed_workers?: number; active_workers?: number; global?: Record<string, number> };
  warnings: string[];
};
type Worker = {
  slot: string;
  state: string;
  client: string | null;
  domain: string | null;
  method: string | null;
  path: string | null;
  seconds_since: number | null;
  request_ms: number | null;
  observation: string;
};
type Detail = Sample & { workers: Worker[]; total_workers: number; details_expired: boolean };
const labels: Record<string, string> = {
  ok: 'Recogida correcta',
  partial: 'Datos parciales',
  error: 'Error de recogida',
};

export function ApacheDiagnostics({ serviceId }: { serviceId: string }) {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [selected, setSelected] = useState('');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState('');
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    api<{ items: Sample[] }>(`/services/${serviceId}/observations`)
      .then((data) => {
        if (active) {
          setSamples(data.items);
          setSelected((id) => id || data.items[0]?.id || '');
        }
      })
      .catch((err) => {
        if (active) setError(err.message);
      });
    return () => {
      active = false;
    };
  }, [serviceId, refresh]);
  useEffect(() => {
    if (!selected) return;
    let active = true;
    setDetail(null);
    api<Detail>(`/observations/${selected}?offset=${offset}`)
      .then((data) => {
        if (active) setDetail(data);
      })
      .catch((err) => {
        if (active) setError(err.message);
      });
    return () => {
      active = false;
    };
  }, [selected, offset]);
  return (
    <section className="apache-diagnostics">
      <p>
        Son observaciones instantáneas, no un registro de todas las visitas. Los workers inactivos
        pueden mostrar su última petición.
      </p>
      <button
        className="secondary"
        onClick={() => {
          setError('');
          setRefresh((x) => x + 1);
        }}
      >
        Actualizar histórico
      </button>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!samples.length ? (
        <p>
          Aún no hay muestras. El worker recoge este servicio según su intervalo mientras esté
          habilitado.
        </p>
      ) : (
        <>
          <label>
            Muestra (últimas 50)
            <select
              value={selected}
              onChange={(e) => {
                setSelected(e.target.value);
                setOffset(0);
              }}
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {new Date(s.observed_at).toLocaleString()} · {labels[s.status]} · revisión{' '}
                  {s.revision}
                </option>
              ))}
            </select>
          </label>
          {detail && (
            <>
              <div className="diagnostic-metrics">
                <p>
                  <strong>{detail.metrics.observed_workers ?? '—'}</strong> Workers observados
                </p>
                <p>
                  <strong>{detail.metrics.active_workers ?? '—'}</strong> En estado activo
                </p>
                <p>
                  <strong>{detail.metrics.global?.BusyWorkers ?? '—'}</strong> Ocupados (?auto)
                </p>
                <p>
                  <strong>{detail.metrics.global?.IdleWorkers ?? '—'}</strong> Disponibles (?auto)
                </p>
              </div>
              {detail.warnings.map((w) => (
                <p className="error" key={w}>
                  {w}
                </p>
              ))}
              <p>
                Fecha: {new Date(detail.observed_at).toLocaleString()} · Revisión {detail.revision}.
                SS indica segundos desde el inicio de la petición más reciente; Req es su tiempo en
                milisegundos. No equivalen a latencia actual en todos los estados.
              </p>
              {detail.metrics.global && (
                <details>
                  <summary>Contadores y métricas globales de Apache</summary>
                  <dl>
                    {Object.entries(detail.metrics.global).map(([key, value]) => (
                      <div key={key}>
                        <dt>{key}</dt>
                        <dd>{value.toLocaleString()}</dd>
                      </div>
                    ))}
                  </dl>
                  <p>
                    Los contadores acumulados corresponden a todo el servidor desde su reinicio. No
                    se atribuyen a los dominios de esta muestra.
                  </p>
                </details>
              )}
              {detail.details_expired ? (
                <p>El detalle de IP y rutas ha vencido (30 días).</p>
              ) : (
                <>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Worker</th>
                          <th>Estado</th>
                          <th>Observación</th>
                          <th>IP</th>
                          <th>Dominio</th>
                          <th>Petición sin parámetros</th>
                          <th>SS (s)</th>
                          <th>Req (ms)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.workers.map((w, i) => (
                          <tr key={`${w.slot}-${i}`}>
                            <td>{w.slot}</td>
                            <td>{w.state}</td>
                            <td>
                              {w.observation === 'current' ? 'Estado activo' : 'Última petición'}
                            </td>
                            <td>{w.client ?? '—'}</td>
                            <td>{w.domain ?? '—'}</td>
                            <td>
                              {w.method} {w.path ?? '—'}
                            </td>
                            <td>{w.seconds_since ?? '—'}</td>
                            <td>{w.request_ms ?? '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p>
                    {detail.total_workers ? offset + 1 : 0}–
                    {Math.min(offset + 100, detail.total_workers)} de {detail.total_workers} workers
                  </p>
                  <button
                    className="secondary"
                    disabled={!offset}
                    onClick={() => setOffset((x) => Math.max(0, x - 100))}
                  >
                    Anteriores
                  </button>{' '}
                  <button
                    className="secondary"
                    disabled={offset + 100 >= detail.total_workers}
                    onClick={() => setOffset((x) => x + 100)}
                  >
                    Siguientes
                  </button>
                </>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}
