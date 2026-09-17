import { useState } from 'react';
import { Activity, Cpu, Database, Globe2, HardDrive, Network } from 'lucide-react';
import { TimelineBins } from './IncidentTimeline';
import type { IncidentSummary } from './IncidentTimeline';
import { memory, numeric } from './incidentText';

export type Monitor = {
  id: string;
  name: string;
  state: string;
  status_text: string;
  reason: string;
  value: number | null;
  unit: string | null;
  display_bytes: number | null;
  value_label: string;
  latest_at: string | null;
  action: string;
  context: {
    label: string;
    text?: string;
    value?: number;
    unit?: string;
    display_bytes?: number | null;
  }[];
  ranking?: {
    domain: string;
    service: string;
    service_id: string;
    average: number;
    current: number | null;
    peak: number;
    bins: { start: string; value: number | null; samples: number }[];
  }[];
  bins: IncidentSummary['bins'];
};
const icons = {
  ram_free: Database,
  swap_free: HardDrive,
  cpu: Cpu,
  load: Activity,
  domains: Globe2,
  ips: Network,
};
function valueText(item: {
  value?: number | null;
  unit?: string | null;
  display_bytes?: number | null;
}) {
  if (item.display_bytes != null) return memory(item.display_bytes);
  if (item.value == null) return 'Sin dato';
  return `${numeric(item.value)}${item.unit && item.unit !== 'valor de origen' ? ` ${item.unit}` : ''}`;
}
export function OperationalMonitors({
  summary,
  openIncidents,
  showCharts,
  configure,
}: {
  summary: IncidentSummary;
  openIncidents: () => void;
  showCharts?: () => void;
  configure?: () => void;
}) {
  const [selection, setSelection] = useState<{ row: string; index: number } | null>(null);
  const rows = summary.monitors ?? [];
  const referenceTime = new Date(summary.end).getTime();
  const recentReadings = rows.filter(
    (row) =>
      row.latest_at &&
      referenceTime - new Date(row.latest_at).getTime() >= 0 &&
      referenceTime - new Date(row.latest_at).getTime() <= 600000,
  );
  const attention = rows.filter((row) => ['warning', 'critical'].includes(row.state));
  const uncertain = rows.filter((row) => ['unknown', 'learning'].includes(row.state)).length;
  return (
    <section
      className="incident-summary operational-monitors"
      aria-label="Estado de los indicadores del servidor"
    >
      <div className="incident-summary-heading">
        <div>
          <h2>Qué necesita atención</h2>
          <p>
            {attention.length
              ? `${attention.length} ${attention.length === 1 ? 'indicador para revisar' : 'indicadores para revisar'}`
              : uncertain
                ? 'Evaluación todavía parcial'
                : 'Sin avisos en los indicadores evaluados'}{' '}
            · {summary.open} {summary.open === 1 ? 'incidencia abierta' : 'incidencias abiertas'}
            {uncertain > 0 ? ` · ${uncertain} indicadores sin evaluación suficiente` : ''}
          </p>
        </div>
        <button className="secondary" onClick={openIncidents}>
          Ver incidentes
        </button>
      </div>
      <p className="monitor-intro" role="status">
        {recentReadings.length > 0
          ? `Recibiendo datos · ${recentReadings.length}/${rows.length} indicadores con lecturas en los últimos 10 minutos.`
          : 'Sin lecturas recientes en estos indicadores. Revisa el estado de las fuentes.'}
        {uncertain > 0 &&
          ' Recoger datos y disponer de histórico suficiente son estados distintos; abre Detalle para ver qué falta.'}
      </p>
      <p className="monitor-intro">
        Recursos y actividad del servidor · ahora y últimas 24 horas. Las conexiones son capturas
        cada 5 minutos, no el total de visitas.
      </p>
      <div className="monitor-column-head" aria-hidden="true">
        <span>Indicador y lectura actual</span>
        <span>Estado y evolución · 24 h</span>
      </div>
      {rows.map((row) => {
        const Icon = icons[row.id as keyof typeof icons] ?? Activity;
        return (
          <article className={`monitor-row ${row.state}`} key={row.id} aria-label={row.name}>
            <div className="monitor-identity">
              <Icon size={16} aria-hidden="true" />
              <div>
                <h3>{row.name}</h3>
                <strong className="monitor-value">{valueText(row)}</strong>
                <small>
                  {row.value_label}
                  {row.unit === 'valor de origen' ? ' · escala de origen' : ''}
                </small>
              </div>
            </div>
            <div className="monitor-status-history">
              <span className={`service-timeline-status ${row.state}`}>
                <span aria-hidden="true">
                  {row.state === 'observed'
                    ? '✓'
                    : row.state === 'critical'
                      ? '!'
                      : row.state === 'warning'
                        ? '△'
                        : row.state === 'learning'
                          ? '◷'
                          : '·'}
                </span>{' '}
                {row.status_text}
              </span>
              <TimelineBins
                indicator
                bins={row.bins}
                selected={selection?.row === row.id ? selection.index : null}
                setSelected={(index) =>
                  setSelection(index === null ? null : { row: row.id, index })
                }
              />
            </div>
            <details className="monitor-explanation">
              <summary aria-label={`Ver detalle de ${row.name.toLowerCase()}`}>Detalle</summary>
              <p>{row.reason}</p>
              <p>
                Última lectura:{' '}
                {row.latest_at ? new Date(row.latest_at).toLocaleString('es') : 'No disponible'}.
              </p>
              {row.context.length > 0 && (
                <ul>
                  {row.context.map((item, index) => (
                    <li key={index}>
                      <strong>{item.label}</strong>: {item.text ?? valueText(item)}
                    </li>
                  ))}
                </ul>
              )}
              <div className="monitor-actions">
                {showCharts && (
                  <button className="secondary" onClick={showCharts}>
                    {['resources', 'latency'].includes(row.action)
                      ? 'Abrir gráficos de recursos'
                      : 'Abrir rankings de actividad'}
                  </button>
                )}
                {['warning', 'critical'].includes(row.state) && (
                  <button className="secondary" onClick={openIncidents}>
                    Consultar incidencias y evidencias
                  </button>
                )}
                {configure && (
                  <button className="secondary" onClick={configure}>
                    Configurar alertas y métricas
                  </button>
                )}
              </div>
            </details>
          </article>
        );
      })}
      <div className="timeline-scale">
        <span>
          {new Date(summary.start).toLocaleString('es', {
            day: '2-digit',
            month: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
          })}
        </span>
        <span>Ahora</span>
      </div>
      <p className="timeline-legend">
        <span>
          <i className="observed" />
          Sin avisos registrados
        </span>
        <span>
          <i className="warning" />
          Revisar
        </span>
        <span>
          <i className="critical" />
          Prioridad alta
        </span>
        <span>
          <i className="informational" />
          Observación
        </span>
        <span>
          <i className="unknown" />
          Sin evaluación suficiente
        </span>
      </p>
      {(rows.find((row) => row.id === 'domains')?.ranking?.length ?? 0) > 0 && (
        <div className="domain-leaders">
          <h3>Dominios más activos · 24 h</h3>
          <p>
            Ordenados por conexiones activas medias en las capturas. Cada barra muestra la media de
            30 min; gris = sin datos.
          </p>
          <div className="domain-leader heading">
            <span>Dominio</span>
            <span>Ahora / pico</span>
            <span>Evolución · misma escala</span>
          </div>
          {rows
            .find((row) => row.id === 'domains')!
            .ranking!.map((entry) => {
              const scale = Math.max(
                1,
                ...rows
                  .find((row) => row.id === 'domains')!
                  .ranking!.flatMap((item) => item.bins.map((bin) => bin.value ?? 0)),
              );
              return (
                <div className="domain-leader" key={`${entry.service_id}:${entry.domain}`}>
                  <span className="domain-leader-name">
                    <strong>{entry.domain}</strong>
                    <small>
                      {entry.service} · media {numeric(entry.average)}
                    </small>
                  </span>
                  <span>
                    {entry.current === null ? '—' : numeric(entry.current)} / {numeric(entry.peak)}
                  </span>
                  <svg
                    viewBox="0 0 240 30"
                    role="img"
                    aria-label={`Evolución de ${entry.domain}, media ${entry.average}, pico ${entry.peak}`}
                  >
                    {entry.bins.map((bin, index) => (
                      <rect
                        key={index}
                        x={index * 5}
                        y={bin.value === null ? 26 : 30 - Math.max(1, (bin.value / scale) * 30)}
                        width="4"
                        height={bin.value === null ? 4 : Math.max(1, (bin.value / scale) * 30)}
                        fill={bin.value === null ? '#d8dfdc' : '#478475'}
                      >
                        <title>
                          {new Date(bin.start).toLocaleString('es')} ·{' '}
                          {bin.value === null
                            ? 'Sin datos'
                            : `${bin.value} conexiones medias · ${bin.samples} capturas`}
                        </title>
                      </rect>
                    ))}
                  </svg>
                </div>
              );
            })}
        </div>
      )}
      <p className="monitor-footnote">
        Cada tramo son 30 minutos. Pasa el ratón, usa el teclado o toca para ver el detalle. Los
        huecos no confirman un estado correcto.
      </p>
      {summary.partial && <p>El histórico mostrado es parcial por límite de registros.</p>}
    </section>
  );
}
