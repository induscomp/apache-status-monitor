import { useState } from 'react';
import { subjectText } from './incidentText';

export type IncidentSummary = {
  start: string;
  end: string;
  partial: boolean;
  open: number;
  critical: number;
  resolved: number;
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
  critical: 'Incidencia de prioridad alta',
  warning: 'Incidencia de prioridad media',
  resolved: 'Incidencia resuelta',
  observed: 'Sin incidencias registradas',
  unknown: 'Cobertura insuficiente',
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
}: {
  summary: IncidentSummary;
  openIncidents: () => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const detail = selected === null ? null : summary.bins[selected];
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
        Un mismo aviso abierto ocupa varios tramos. La franja roja no significa ataques continuos ni
        nuevos ataques en cada tramo.
      </p>
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
          {summary.bins.map((bin, i) => (
            <button
              key={bin.start}
              className={`incident-segment ${bin.state}`}
              aria-label={`${format(bin.start)}–${format(bin.end)}: ${labels[bin.state]}, ${bin.incidents} incidencias, ${bin.samples} muestras`}
              aria-describedby={selected === i ? 'incident-time-detail' : undefined}
              onMouseEnter={() => setSelected(i)}
              onFocus={() => setSelected(i)}
              onBlur={() => setSelected(null)}
              onClick={() => setSelected(i)}
            />
          ))}
        </div>
        {detail && (
          <div className="incident-time-detail" role="tooltip" id="incident-time-detail">
            <strong>
              {format(detail.start)} — {format(detail.end)}
            </strong>
            <p>
              {labels[detail.state]} · {detail.incidents} incidencias · {detail.resolved} resueltas
              en el tramo.
            </p>
            <p>
              {detail.samples} muestras.{' '}
              {detail.coverage === 'complete'
                ? 'Cobertura de Apache y MRTG disponible.'
                : detail.coverage === 'partial'
                  ? 'Cobertura parcial: faltan lecturas comparables.'
                  : 'Sin muestras: no permite evaluar el estado.'}
            </p>
            {detail.details.map((d, i) => (
              <p key={i}>
                {subjectText(d.subject)} ·{' '}
                {d.subject.startsWith('resource:')
                  ? `MRTG, correlacionado con ${d.service}`
                  : d.service}
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
