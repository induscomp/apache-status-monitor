import { useEffect, useState } from 'react';
import { api } from './api';
export type Source = {
  id: string;
  name: string;
  kind: string;
  status: string;
  last_at: string | null;
};
export const sourceLabels: Record<string, string> = {
  ok: 'Recogida disponible',
  partial: 'Datos parciales',
  error: 'Error de recogida',
  stale: 'Desactualizado',
  waiting: 'Esperando recogida',
  paused: 'Pausado',
  archived: 'Archivado',
};
export function SourceList({ sources, open }: { sources: Source[]; open?: (id: string) => void }) {
  return (
    <div className="source-list">
      {!sources.length && <p>Sin fuentes configuradas.</p>}
      {sources.map((s) => (
        <div key={s.id}>
          <strong>{s.name}</strong>
          <span>
            {s.kind === 'apache_status' ? 'Apache Status' : s.kind === 'mrtg' ? 'MRTG' : 'GoAccess'}{' '}
            · {sourceLabels[s.status] || s.status}
          </span>
          {s.last_at && <small>Última consulta: {new Date(s.last_at).toLocaleString('es')}</small>}
          {open && (
            <button className="text-button" onClick={() => open(s.id)}>
              Ver detalle de {s.name}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
type Card = {
  priority?: string;
  id: string;
  name: string;
  description: string;
  state: string;
  open_incidents: number;
  sources: Source[];
};
export function Dashboard({
  open,
  configureMail,
}: {
  open: (id: string) => void;
  configureMail: () => void;
}) {
  const [data, setData] = useState<{ items: Card[]; total: number; open_incidents: number } | null>(
    null,
  );
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    const refresh = () =>
      api<typeof data>(`/dashboard?offset=${offset}`)
        .then((v) => {
          if (live) {
            setData(v);
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
  }, [offset]);
  const labels: Record<string, string> = {
    incident: 'Incidentes abiertos',
    attention: 'Revisar cobertura de las fuentes',
    waiting: 'Pendiente de datos',
    observing: 'Sin incidencias registradas',
    archived: 'Archivado',
  };
  return (
    <div className="server-overview">
      <div className="overview-card">
        <h2>Mis servidores</h2>
        <p>
          {data?.total ?? 0} servidores · {data?.open_incidents ?? 0} incidentes abiertos
        </p>
        <button className="secondary" onClick={configureMail}>
          Configurar correo de la cuenta
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      {data?.items.length === 0 && (
        <p>
          Añade tu primer servidor. Después selecciona sus fuentes disponibles: Apache Status, MRTG
          o GoAccess.
        </p>
      )}
      <div className="overview-grid">
        {data?.items.map((s) => (
          <article
            className={`overview-card server-card ${s.state} ${s.priority || ''}`}
            key={s.id}
          >
            <h2>{s.name}</h2>
            <p>{s.description}</p>
            <strong>{labels[s.state]}</strong>
            <p>
              {s.open_incidents} incidentes abiertos · {s.sources.length} fuentes configuradas
            </p>
            <SourceList sources={s.sources} />
            <button className="primary" onClick={() => open(s.id)}>
              Ver servidor {s.name}
            </button>
          </article>
        ))}
      </div>
      {data && data.total > 20 && (
        <div className="overview-controls">
          <button disabled={!offset} onClick={() => setOffset(offset - 20)}>
            Servidores anteriores
          </button>
          <button disabled={offset + 20 >= data.total} onClick={() => setOffset(offset + 20)}>
            Servidores siguientes
          </button>
        </div>
      )}
    </div>
  );
}
