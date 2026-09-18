import { useEffect, useState } from 'react';
import { api } from './api';
import { SupportMail } from './SupportMail';
import { numeric } from './incidentText';
import './overview.css';

type Row = {
  high_priority: boolean;
  support_ips: string[];
  support_evidence: {
    ip: string;
    domain: string;
    endpoint: string;
    captures: string[];
    geo: Row['geo'];
  }[];
  key: string;
  score: number;
  flagged: boolean;
  status: string;
  observations: number;
  peak: number;
  samples: number;
  first: string;
  last: string;
  retained: number;
  signatures: number;
  probes: number;
  reasons: string[];
  ips: string[];
  domains: string[];
  domain_samples?: Record<string, string[]>;
  endpoints: Record<string, number>;
  shared: { target: string; ips: string[] }[];
  reference: { median: number; samples: number; kind?: string } | null;
  geo: { country: string | null; organization: string | null; asn: number | null } | null;
};
type Window = {
  service: string;
  service_id: string;
  fresh: boolean;
  coverage: number;
  samples: number;
  expected: number;
  start: string;
  end: string;
  ips: Row[];
  networks: Row[];
};
const date = (s: string) =>
  new Date(s).toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
function attribution(geo: Row['geo']) {
  const country = geo?.country
    ? new Intl.DisplayNames(['es'], { type: 'region' }).of(geo.country) || geo.country
    : 'País desconocido';
  return `${country} · ${geo?.organization || 'Proveedor desconocido'}${geo?.asn ? ` · AS${geo.asn}` : ''}`;
}
function supportReport(serverId: string, item: Window, row: Row) {
  return [
    'Solicitud de revisión y bloqueo de IPs con actividad sospechosa',
    `Servidor: ${serverId} · fuente: ${item.service}`,
    `Ventana UTC: ${item.start} — ${item.end}`,
    `Cobertura: ${item.samples}/${item.expected} capturas · ${item.fresh ? 'lectura reciente' : 'lectura desactualizada'}`,
    `Agrupación de análisis: ${row.key} (no se solicita bloquear el prefijo completo)`,
    ...row.reasons,
    '',
    'IP concretas candidatas a bloqueo:',
    ...row.support_ips,
    '',
    'Evidencia por IP, dominio y ruta (horas UTC):',
    ...row.support_evidence.map(
      (e) =>
        `${e.ip} | ${attribution(e.geo)} | ${e.domain || 'Dominio desconocido'} | ${e.endpoint} | ${e.captures.join(', ')}`,
    ),
    '',
    'Capturas cada 5 min; incluyen últimas peticiones retenidas recientes. No son logs completos ni prueban explotación exitosa. País/ASN: atribución de la base local actual, no criterio de culpabilidad.',
  ].join('\n');
}
function downloadReport(report: string) {
  const url = URL.createObjectURL(new Blob([report], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'informe-ips-soporte.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function SupportEvidence({
  serverId,
  item,
  row,
  copy,
}: {
  serverId: string;
  item: Window;
  row: Row;
  copy: (value: string) => Promise<void>;
}) {
  if (!row.high_priority) return null;
  const report = supportReport(serverId, item, row);
  return (
    <details>
      <summary>{row.support_ips.length} IP candidatas a bloqueo · evidencias para soporte</summary>
      <p>{row.support_ips.join(' · ')}</p>
      <p>{[...new Set(row.support_evidence.map((e) => attribution(e.geo)))].join(' / ')}</p>
      <div className="overview-controls">
        <button type="button" onClick={() => void copy(row.support_ips.join('\n'))}>
          Copiar IPs
        </button>
        <button type="button" onClick={() => void copy(report)}>
          Copiar informe para soporte
        </button>
        <button type="button" onClick={() => downloadReport(report)}>
          Descargar informe
        </button>
      </div>
      <textarea
        aria-label="Informe para soporte"
        readOnly
        rows={8}
        value={report}
        style={{ width: '100%' }}
      />
    </details>
  );
}
export function IpActivity({
  serverId,
  csrf,
  compact = false,
}: {
  serverId: string;
  csrf: string;
  compact?: boolean;
}) {
  const [minutes, setMinutes] = useState(compact ? 60 : 30);
  const [group, setGroup] = useState<'ips' | 'networks'>('ips');
  const [data, setData] = useState<{ items: Window[] } | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');
  const [showAll, setShowAll] = useState(false);
  const [onlySignals, setOnlySignals] = useState(true);
  useEffect(() => {
    let live = true;
    setData(null);
    setShowAll(false);
    const refresh = async () => {
      try {
        const next = await api<{ items: Window[] }>(
          `/servers/${serverId}/ip-activity?minutes=${minutes}`,
        );
        if (live) {
          setData(next);
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
  }, [serverId, minutes]);
  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied('Copiado al portapapeles.');
    } catch {
      setCopied('No se pudo copiar. Selecciona el texto del informe y cópialo manualmente.');
    }
  }
  if (compact) {
    const campaigns =
      data?.items.flatMap((item) =>
        item.networks.filter((row) => row.high_priority).map((row) => ({ item, row })),
      ) || [];
    campaigns.sort(
      (a, b) => b.row.score - a.row.score || b.row.support_ips.length - a.row.support_ips.length,
    );
    const allIps = [...new Set(campaigns.flatMap(({ row }) => row.support_ips))].sort();
    const completeReport = [
      'IP candidatas a bloqueo (sin duplicados):',
      ...allIps,
      '',
      ...campaigns.map(({ item, row }) => supportReport(serverId, item, row)),
    ].join('\n');
    return (
      <section className="overview-card" aria-label="Alertas importantes de IP">
        <h3>Alertas importantes de IP · última hora</h3>
        {error && <p role="alert">{error}</p>}
        {!data && !error && <p>Comprobando patrones multidominio…</p>}
        {data && !campaigns.length && (
          <p>
            No se han observado campañas multidominio en las capturas disponibles.
            {data.items.some((item) => !item.fresh || item.coverage < 1) &&
              ' Hay lecturas ausentes o desactualizadas.'}
          </p>
        )}
        {campaigns.length > 0 && (
          <details>
            <summary>
              {campaigns.length} grupos · {allIps.length} IP candidatas · listado completo para
              soporte
            </summary>
            <div className="overview-controls">
              <button type="button" onClick={() => void copy(allIps.join('\n'))}>
                Copiar todas las IP candidatas
              </button>
              <button type="button" onClick={() => downloadReport(completeReport)}>
                Descargar informe completo
              </button>
            </div>
            <textarea
              aria-label="Informe completo para soporte"
              readOnly
              rows={8}
              value={completeReport}
              style={{ width: '100%' }}
            />
          </details>
        )}
        {(showAll ? campaigns : campaigns.slice(0, 3)).map(({ item, row }) => (
          <article
            key={item.service_id + row.key}
            style={{ borderLeft: '4px solid #bd4936', padding: '8px 12px', margin: '8px 0' }}
          >
            <strong>Prioridad alta · posible campaña contra varios dominios</strong>
            <p>
              {row.key} · {row.support_ips.length} IP con evidencia sensible ·{' '}
              {new Set(row.support_evidence.map((e) => e.domain).filter(Boolean)).size} dominios ·{' '}
              {date(row.first)}–{date(row.last)} · {item.service}
            </p>
            <p>{[...new Set(row.support_evidence.map((e) => attribution(e.geo)))].join(' / ')}</p>
            {(!item.fresh || item.coverage < 1) && (
              <p>
                Lecturas incompletas o desactualizadas · cobertura {item.samples}/{item.expected}.
              </p>
            )}
            <SupportEvidence serverId={serverId} item={item} row={row} copy={copy} />
          </article>
        ))}
        {campaigns.length > 3 && (
          <button type="button" onClick={() => setShowAll(!showAll)}>
            {showAll
              ? 'Mostrar solo los 3 prioritarios'
              : `Ver los otros ${campaigns.length - 3} grupos`}
          </button>
        )}
        <SupportMail key={serverId} serverId={serverId} csrf={csrf} />
        <span role="status">{copied}</span>
      </section>
    );
  }
  return (
    <section className="server-overview security-overview" aria-label="Ataques y actividad IP">
      <header>
        <h2>Ataques y actividad IP</h2>
        <span>Observaciones de Apache · actualización cada 5 min</span>
      </header>
      <p>
        Rutas de posible explotación, actividad anómala y coincidencias entre IP vecinas. Son
        señales para investigar, no ataques confirmados.
      </p>
      <div className="overview-controls">
        <label>
          Ventana{' '}
          <select
            aria-label="Ventana"
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
          >
            {[5, 10, 25, 30, 60].map((m) => (
              <option key={m} value={m}>
                {m} minutos
              </option>
            ))}
          </select>
        </label>
        <label>
          Agrupar por{' '}
          <select
            aria-label="Agrupar por"
            value={group}
            onChange={(e) => setGroup(e.target.value as 'ips' | 'networks')}
          >
            <option value="ips">IP individual</option>
            <option value="networks">Familias IPv4 /24 · IPv6 /64</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={onlySignals}
            onChange={(e) => setOnlySignals(e.target.checked)}
          />{' '}
          Solo señales y rutas sensibles
        </label>
      </div>
      <SupportMail key={serverId} serverId={serverId} csrf={csrf} />
      <p role="status">{copied}</p>
      {error && <p role="alert">{error}</p>}
      {!data && !error && <p>Comparando ventanas e histórico…</p>}
      {data?.items.map((item) => (
        <div key={item.service_id}>
          <h3>
            {item.service} · {date(item.start)}–{date(item.end)}
          </h3>
          <p>
            {item.fresh ? 'Recogida reciente' : 'Sin lectura reciente'} · cobertura {item.samples}/
            {item.expected} capturas · {item[group].filter((r) => r.flagged).length} patrones para
            revisar.
          </p>
          {item.coverage < 1 && (
            <p className="monitor-footnote">
              La ventana tiene huecos. Sus observaciones siguen siendo visibles; no confirman
              ausencia de actividad ni recuperaciones.
            </p>
          )}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{group === 'ips' ? 'IP / proveedor' : 'Familia de red'}</th>
                  <th>Actividad en la ventana</th>
                  <th>Motivo de revisión</th>
                  <th>Dominios y rutas</th>
                </tr>
              </thead>
              <tbody>
                {item[group]
                  .filter((r) => !onlySignals || r.signatures > 0 || r.score > 0)
                  .map((r) => (
                    <tr key={r.key}>
                      <td>
                        <strong>{r.key}</strong>
                        {r.geo && (
                          <p>
                            {r.geo.country || 'País desconocido'} ·{' '}
                            {r.geo.organization || 'Proveedor desconocido'}{' '}
                            {r.geo.asn ? `AS${r.geo.asn}` : ''}
                          </p>
                        )}
                        <button type="button" onClick={() => void copy(r.key)}>
                          {group === 'ips' ? 'Copiar IP' : 'Copiar rango'}
                        </button>
                      </td>
                      <td>
                        {r.peak} conexiones simultáneas como máximo
                        <br />
                        {r.samples} capturas · {r.ips.length} IP · {r.domains.length} dominios
                        <p>
                          Primera/última: {date(r.first)} / {date(r.last)}
                        </p>
                        <small>
                          {r.observations} conexiones sumadas en capturas, no visitas.
                          {r.reference
                            ? ` ${r.reference.kind === 'previous_window' ? 'Ventana anterior (comparación corta)' : 'Referencia de ventanas iguales'}: ${numeric(r.reference.median)} (${r.reference.samples} ventanas).`
                            : ' Todavía sin línea base propia suficiente.'}
                        </small>
                      </td>
                      <td>
                        <strong className={r.flagged ? 'security-label watch' : ''}>
                          {r.status}
                        </strong>
                        <p>Prioridad {r.score}/100 · no es probabilidad</p>
                        <SupportEvidence serverId={serverId} item={item} row={r} copy={copy} />
                        <ul>
                          {r.reasons.map((reason) => (
                            <li key={reason}>{reason}</li>
                          ))}
                        </ul>
                      </td>
                      <td>
                        <details>
                          <summary>
                            {r.domains.length} dominios · {r.signatures} huellas sensibles
                          </summary>
                          <p>{r.domains.join(' · ') || 'Dominio no identificado'}</p>
                          {Object.entries(r.domain_samples || {}).map(([domain, times]) => (
                            <p key={domain}>
                              {domain}: {times.map(date).join(' · ')}
                            </p>
                          ))}
                          {Object.entries(r.endpoints).map(([path, count]) => (
                            <p key={path}>
                              {path} · {count} huellas
                            </p>
                          ))}
                          {r.shared.map((s) => (
                            <p key={s.target}>
                              Coincidencia: {s.target}
                              <br />
                              {s.ips.join(' · ')}
                            </p>
                          ))}
                          {group === 'networks' && <p>IP observadas: {r.ips.join(' · ')}</p>}
                          <small>
                            {r.retained} huellas son últimas peticiones recientes conservadas por
                            Apache. No se cuentan como conexiones actuales ni prueban accesos
                            nuevos.
                          </small>
                        </details>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {!item[group].some((r) => !onlySignals || r.signatures > 0 || r.score > 0) && (
            <p>
              No se han observado señales en esta ventana. Las capturas de cinco minutos pueden no
              ver intentos breves entre lecturas.
            </p>
          )}
        </div>
      ))}
      {data && !data.items.length && (
        <p>Configura un servicio Apache para analizar sus capturas.</p>
      )}
      <details>
        <summary>Cómo interpretar IP vecinas y alertas</summary>
        <p>
          Los prefijos /24 y /64 son agrupaciones de análisis, no una identidad común. Se destaca
          que varias IP coincidan en dominio y ruta sensible junto con escaneo o desviación
          histórica. NAT, proxies y proveedores compartidos pueden agrupar usuarios legítimos. El
          monitor nunca bloquea un rango.
        </p>
        <p>
          Las huellas se deduplican por worker, IP, dominio, método, ruta y Req dentro de cada
          ventana. Esta deduplicación es conservadora y no reconstruye peticiones únicas. Las
          huellas retenidas sin antigüedad interpretable o de más de cinco minutos se excluyen.
          HTTP/2 puede ocultar actividad al scoreboard.
        </p>
        <p>
          Los incidentes requieren confirmaciones entre capturas. Login/AJAX habituales no abren
          incidentes por sí solos. El sondeo repetido de archivos de configuración o exposición se
          puede señalar incluso sin histórico propio de la IP, indicando su fundamento.
        </p>
      </details>
    </section>
  );
}
