import { useEffect, useState } from 'react';
import { api } from './api';
import { sourceLabels } from './Dashboard';
type Row = {
  label: string;
  hits: number | null;
  visitors: number | null;
  bytes: number | null;
  method: string;
};
type Report = {
  generated_at: string | null;
  observed_at: string;
  summary: Record<string, string | number | null>;
  panels: Record<string, Row[]>;
};
export function GoAccessDiagnostics({ serviceId }: { serviceId: string }) {
  const [data, setData] = useState<{
    status: string;
    checked_at: string | null;
    report: Report | null;
    note: string;
    warnings: string[];
    history: { id: string; generated_at: string | null; summary: Report['summary'] }[];
  } | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    const refresh = () =>
      api<typeof data>(`/services/${serviceId}/goaccess`)
        .then((d) => {
          if (live) {
            setData(d);
            setError('');
          }
        })
        .catch((e) => {
          if (live) setError(e.message);
        });
    void refresh();
    const timer = setInterval(refresh, 30000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [serviceId]);
  const names: Record<string, string> = {
    total_requests: 'Peticiones procesadas',
    valid_requests: 'Peticiones válidas',
    failed_requests: 'Líneas de log no procesadas',
    unique_visitors: 'Visitantes según GoAccess',
    bandwidth: 'Bytes transferidos',
    excluded_hits: 'Peticiones excluidas',
    unique_not_found: 'Recursos no encontrados',
    start_date: 'Inicio del periodo',
    end_date: 'Fin del periodo',
  };
  const panels: Record<string, string> = {
    vhosts: 'Dominios del informe',
    requests: 'Peticiones del informe',
    hosts: 'IPs del informe',
    status_codes: 'Códigos HTTP',
    visitors: 'Actividad por fecha',
  };
  return (
    <div className="server-overview">
      {error && <p role="alert">{error}</p>}
      {!data ? (
        <p>Cargando GoAccess…</p>
      ) : (
        <>
          <h3>GoAccess · {sourceLabels[data.status] || data.status}</h3>
          <p>{data.note}</p>
          {data.warnings.map((w, i) => (
            <p className="notice" key={i}>
              {w}
            </p>
          ))}
          {!data.report ? (
            <p>Esperando primer informe.</p>
          ) : (
            <>
              <p>
                Generado:{' '}
                {data.report.generated_at
                  ? new Date(data.report.generated_at).toLocaleString('es')
                  : 'Fecha no verificable'}{' '}
                · Última consulta:{' '}
                {data.checked_at ? new Date(data.checked_at).toLocaleString('es') : 'Sin dato'}
              </p>
              <div className="resource-grid">
                {Object.entries(data.report.summary).map(([k, v]) => (
                  <div className="overview-card" key={k}>
                    <h3>{names[k] || k}</h3>
                    <strong>
                      {v == null ? 'Sin dato' : typeof v === 'number' ? v.toLocaleString('es') : v}
                    </strong>
                  </div>
                ))}
              </div>
              {Object.entries(data.report.panels).map(([k, rows]) => (
                <details className="overview-card" key={k}>
                  <summary>
                    {panels[k]} ({rows.length} filas disponibles)
                  </summary>
                  <div className="overview-table">
                    <table>
                      <thead>
                        <tr>
                          <th>Elemento</th>
                          <th>Peticiones</th>
                          <th>Visitantes</th>
                          <th>Bytes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((r, i) => (
                          <tr key={i}>
                            <td>
                              {r.method} {r.label}
                            </td>
                            <td>{r.hits?.toLocaleString('es')}</td>
                            <td>{r.visitors?.toLocaleString('es')}</td>
                            <td>{r.bytes?.toLocaleString('es')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              ))}
              <details className="overview-card">
                <summary>Informes distintos guardados ({data.history.length})</summary>
                {data.history.map((h) => (
                  <p key={h.id}>
                    {h.generated_at
                      ? new Date(h.generated_at).toLocaleString('es')
                      : 'Fecha sin verificar'}{' '}
                    · {h.summary.valid_requests ?? 'Sin dato'} peticiones válidas
                  </p>
                ))}
              </details>
            </>
          )}
        </>
      )}
    </div>
  );
}
