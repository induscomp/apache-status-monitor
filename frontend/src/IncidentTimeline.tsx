import { useId, useState } from 'react';
import { OperationalMonitors } from './OperationalMonitors';
import type { Monitor } from './OperationalMonitors';
import { subjectText } from './incidentText';

export type IncidentSummary = {
  monitors?: Monitor[];
  start: string;
  end: string;
  partial: boolean;
  open: number;
  critical: number;
  resolved: number;
  rows?: {
    id: string;
    name: string;
    kind: string;
    status: string;
    state: string;
    partial: boolean;
    history_note: string | null;
    bins: IncidentSummary['bins'];
  }[];
  bins: {
    start: string;
    end: string;
    state: string;
    coverage: string;
    samples: number;
    incidents: number;
    resolved: number;
    details: {
      subject: string;
      service: string;
      opened_at: string;
      resolved_at: string | null;
      severity: string;
    }[];
  }[];
};
const labels: Record<string, string> = {
  critical: 'Prioridad alta',
  warning: 'Aviso: incidencia o lectura incompleta',
  resolved: 'Incidencia resuelta',
  observed: 'Sin incidencias registradas',
  unknown: 'Cobertura insuficiente',
  learning: 'Aprendiendo',
  informational: 'Observación: sin evaluación independiente de anomalías',
};
const format = (value: string) =>
  new Date(value).toLocaleString('es', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
export function IncidentTimeline({
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
  if (summary.monitors)
    return (
      <OperationalMonitors
        summary={summary}
        openIncidents={openIncidents}
        showCharts={showCharts}
        configure={configure}
      />
    );
  return (
    <section className="incident-summary" aria-label="Resumen temporal de incidencias">
      <div className="incident-summary-heading">
        <div>
          <h2>Incidencias · últimas 24 h</h2>
          <p>
            <strong>{summary.open}</strong> abiertas · <strong>{summary.critical}</strong> de
            prioridad alta · <strong>{summary.resolved}</strong> resueltas
          </p>
        </div>
        <button className="secondary" onClick={openIncidents}>
          Ver incidentes
        </button>
      </div>
      <p>
        Una fila por servicio. Verde: lecturas completas sin avisos detectados. Los huecos no
        indican que todo esté bien. Un aviso puede ocupar varios tramos.
      </p>
      {(
        summary.rows ?? [
          {
            id: 'legacy',
            name: 'Servicios del servidor',
            kind: '',
            status: '',
            state: '',
            partial: false,
            history_note: null,
            bins: summary.bins,
          },
        ]
      ).map((row) => (
        <div className="service-timeline-row" key={row.id}>
          <div className="service-timeline-heading">
            <strong>{row.name}</strong>
            {row.status && (
              <span className={`service-timeline-status ${row.state}`}>
                {row.state === 'critical'
                  ? 'Alerta alta'
                  : row.state === 'warning' && row.status === 'ok'
                    ? 'Aviso abierto'
                    : (statusLabels[row.status] ?? 'Sin evaluar')}
              </span>
            )}
          </div>
          <TimelineBins
            bins={row.bins}
            selected={selection?.row === row.id ? selection.index : null}
            setSelected={(index) => setSelection(index === null ? null : { row: row.id, index })}
          />
          {row.history_note && <small>{row.history_note}</small>}
          {row.partial && <small>Histórico parcial por límite de lecturas.</small>}
        </div>
      ))}
      <div className="timeline-scale">
        <span>{format(summary.start)}</span>
        <span>Ahora</span>
      </div>
      <p className="timeline-legend">
        <span>
          <i className="critical" />
          Alta
        </span>
        <span>
          <i className="warning" />
          Media
        </span>
        <span>
          <i className="observed" />
          Sin incidencias registradas
        </span>
        <span>
          <i className="unknown" />
          Sin cobertura suficiente
        </span>
        <span>Tramos de 30 min · pasa el ratón o toca un tramo</span>
      </p>
      {summary.partial && (
        <p>Resumen parcial por límite de registros. Consulta el listado de incidentes.</p>
      )}
    </section>
  );
}

const statusLabels: Record<string, string> = {
  ok: 'OK · sin avisos',
  partial: 'Datos parciales',
  error: 'Error de lectura',
  stale: 'Desactualizado',
  waiting: 'Esperando datos',
  paused: 'En pausa',
  archived: 'Archivado',
};
export function TimelineBins({
  indicator = false,
  bins,
  selected,
  setSelected,
}: {
  indicator?: boolean;
  bins: IncidentSummary['bins'];
  selected: number | null;
  setSelected: (value: number | null) => void;
}) {
  const tooltipId = useId();
  const detail = selected === null ? null : bins[selected];
  return (
    <div
      className="incident-timeline"
      onMouseLeave={() => setSelected(null)}
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          setSelected(null);
          (e.target as HTMLElement).blur();
        }
      }}
    >
      <div className="incident-segments">
        {bins.map((bin, i) => (
          <button
            key={bin.start}
            className={`incident-segment ${bin.state}`}
            aria-label={`${format(bin.start)}–${format(bin.end)}: ${labels[bin.state]}, ${bin.incidents} incidencias, ${bin.samples} muestras`}
            aria-describedby={selected === i ? tooltipId : undefined}
            onMouseEnter={() => setSelected(i)}
            onFocus={() => setSelected(i)}
            onBlur={() => setSelected(null)}
            onClick={() => setSelected(i)}
          />
        ))}
      </div>
      {detail && (
        <div className="incident-time-detail" role="tooltip" id={tooltipId}>
          <strong>
            {format(detail.start)} — {format(detail.end)}
          </strong>
          <p>
            {labels[detail.state]} · {detail.incidents} incidencias · {detail.resolved} resueltas en
            el tramo.
          </p>
          <p>
            {detail.samples} muestras.{' '}
            {detail.coverage === 'complete'
              ? indicator
                ? 'Lecturas completas de este indicador en el tramo.'
                : 'Lecturas recientes y completas de este servicio.'
              : detail.coverage === 'partial'
                ? 'Cobertura parcial: faltan lecturas comparables.'
                : 'Sin muestras: no permite evaluar el estado.'}
          </p>
          {detail.details.map((d, i) => (
            <p key={i}>
              {subjectText(d.subject)} ·{' '}
              {d.subject.startsWith('resource:') ? `${d.service}` : d.service}
              <br />
              Inicio: {format(d.opened_at)}
              {d.resolved_at ? ` · Resolución: ${format(d.resolved_at)}` : ' · Sigue abierto'}
            </p>
          ))}
          {detail.incidents > detail.details.length && (
            <p>Consulta Incidentes para ver todos los detalles.</p>
          )}
        </div>
      )}
    </div>
  );
}
