import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from './api';

type Configuration = {
  verified?: boolean;
  unit?: string;
  factor?: number;
  capacity?: number | null;
  timezone?: string | null;
};
type Point = {
  window: string;
  channel: string;
  statistic: string;
  value: number;
  source: string;
  source_unit: string | null;
  display_value?: number;
  display_unit?: string;
  display_label?: string;
  label?: string;
  normalized_value?: number;
  unit?: string;
};
type Sample = {
  id: string;
  observed_at: string;
  source_at: string | null;
  source_time_text: string | null;
  status: string;
  values: Point[];
  warnings: string[];
  metric_revision: number;
  configuration: Configuration;
};
type Metric = {
  id: string;
  name: string;
  url: string;
  selected: boolean;
  present: boolean;
  revision: number;
  configuration: Configuration;
  latest: Sample | null;
};
type Catalog = {
  discovery: {
    attempted_at: string | null;
    succeeded_at: string | null;
    requested: boolean;
    error: string | null;
  } | null;
  items: Metric[];
};
const windows: Record<string, string> = { d: 'Diaria', w: 'Semanal', m: 'Mensual', y: 'Anual' };
const statistics: Record<string, string> = {
  current: 'Actual',
  average: 'Media',
  maximum: 'Máximo',
  average_peak: 'Media de máximos',
};

export function MrtgDiagnostics({ serviceId, csrf }: { serviceId: string; csrf: string }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [selected, setSelected] = useState('');
  const [history, setHistory] = useState<Sample[]>([]);
  const [sampleId, setSampleId] = useState('');
  const [window, setWindow] = useState('d');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const metric = catalog?.items.find((m) => m.id === selected);
  const sample = history.find((s) => s.id === sampleId) ?? history[0];
  useEffect(() => {
    let active = true;
    api<Catalog>(`/services/${serviceId}/mrtg`)
      .then((data) => {
        if (active) {
          setCatalog(data);
          setSelected((old) => old || data.items[0]?.id || '');
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
    setHistory([]);
    api<{ items: Sample[] }>(`/mrtg/metrics/${selected}/observations`)
      .then((data) => {
        if (active) {
          setHistory(data.items);
          setSampleId(data.items[0]?.id || '');
        }
      })
      .catch((err) => {
        if (active) setError(err.message);
      });
    return () => {
      active = false;
    };
  }, [selected, refresh]);
  async function rediscover() {
    setBusy(true);
    setError('');
    try {
      await api(`/services/${serviceId}/mrtg/discover`, csrf, 'POST', {});
      setNotice('Descubrimiento encolado. El worker lo ejecutará si el servicio está habilitado.');
      setRefresh((x) => x + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo solicitar el descubrimiento.');
    } finally {
      setBusy(false);
    }
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!metric) return;
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError('');
    try {
      await api(`/mrtg/metrics/${metric.id}`, csrf, 'PUT', {
        selected: data.has('selected'),
        verified: data.has('verified'),
        unit: data.get('unit'),
        factor: Number(data.get('factor')),
        capacity: data.get('capacity') ? Number(data.get('capacity')) : null,
        timezone: data.get('timezone') || null,
      });
      setNotice(
        'Configuración guardada. Se aplicará a las siguientes muestras; el histórico conserva su interpretación original.',
      );
      setRefresh((x) => x + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo guardar.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="mrtg-diagnostics apache-diagnostics">
      <p>
        Leemos las estadísticas de las páginas enlazadas desde las imágenes. No se descargan
        gráficos ni se utiliza OCR. Las métricas nuevas se activan inicialmente; puedes desmarcarlas
        aquí.
      </p>
      <button className="secondary" disabled={busy} onClick={() => setRefresh((x) => x + 1)}>
        Actualizar MRTG
      </button>{' '}
      <button className="secondary" disabled={busy} onClick={rediscover}>
        Redescubrir páginas
      </button>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {catalog?.discovery?.error && <p className="error">{catalog.discovery.error}</p>}
      <p>
        {catalog?.items.filter((m) => m.present).length ?? 0} páginas disponibles. Último
        descubrimiento:{' '}
        {catalog?.discovery?.succeeded_at
          ? new Date(catalog.discovery.succeeded_at).toLocaleString()
          : 'pendiente'}
        . {catalog?.discovery?.requested ? 'Redescubrimiento solicitado.' : ''}
      </p>
      {catalog?.items.length ? (
        <>
          <label>
            Métrica MRTG
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {catalog.items.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} ·{' '}
                  {!m.present ? 'Ya no está en el índice' : m.selected ? 'Activa' : 'Pausada'}
                </option>
              ))}
            </select>
          </label>
          {metric && (
            <>
              <p className="endpoint">{metric.url}</p>
              <form key={`${metric.id}-${metric.revision}`} onSubmit={save}>
                <label className="checkbox">
                  <input type="checkbox" name="selected" defaultChecked={metric.selected} />
                  Monitorizar esta página
                </label>
                <details>
                  <summary>Unidades, escala y zona horaria</summary>
                  <p>
                    Los comentarios y las tablas pueden usar escalas distintas. Esta conversión se
                    aplica solo a valores de comentarios; las tablas alternativas conservan sus
                    cifras y etiquetas originales.
                  </p>
                  <label>
                    Unidad de los comentarios
                    <input
                      name="unit"
                      defaultValue={metric.configuration.unit ?? ''}
                      maxLength={40}
                      placeholder="Sin verificar"
                    />
                  </label>
                  <label>
                    Factor de conversión
                    <input
                      name="factor"
                      type="number"
                      step="any"
                      min="0.000000000001"
                      max="1000000000000"
                      defaultValue={metric.configuration.factor ?? 1}
                      required
                    />
                  </label>
                  <label>
                    Zona horaria del origen
                    <input
                      name="timezone"
                      defaultValue={metric.configuration.timezone ?? ''}
                      maxLength={80}
                      placeholder="Zona IANA, si se conoce"
                    />
                  </label>
                  <label>
                    Capacidad total de swap (opcional, en la unidad confirmada)
                    <input
                      name="capacity"
                      type="number"
                      min="0"
                      step="any"
                      defaultValue={metric.configuration.capacity ?? ''}
                    />
                    <small>
                      Solo para swap libre. Capacidad real, no máximo observado. Si queda menos swap
                      libre que este total, el aviso de memoria pasa a rojo.
                    </small>
                  </label>
                  <label className="checkbox">
                    <input
                      name="verified"
                      type="checkbox"
                      defaultChecked={metric.configuration.verified ?? false}
                    />
                    He verificado la unidad y la escala de los comentarios
                  </label>
                </details>
                <button className="primary" disabled={busy}>
                  Guardar métrica
                </button>
              </form>
            </>
          )}
          {!history.length ? (
            <p>Aún no hay muestras de esta métrica.</p>
          ) : (
            <>
              <label>
                Muestra MRTG (últimas 50)
                <select value={sampleId} onChange={(e) => setSampleId(e.target.value)}>
                  {history.map((s) => (
                    <option key={s.id} value={s.id}>
                      {new Date(s.observed_at).toLocaleString()} ·{' '}
                      {s.status === 'error'
                        ? 'Error'
                        : s.status === 'partial'
                          ? 'Con avisos'
                          : 'Correcta'}
                    </option>
                  ))}
                </select>
              </label>
              {sample && (
                <>
                  <p>
                    Recogida: {new Date(sample.observed_at).toLocaleString()}. Actualización en
                    origen:{' '}
                    {sample.source_at
                      ? new Date(sample.source_at).toLocaleString()
                      : (sample.source_time_text ?? 'No disponible')}
                    {!sample.source_at && sample.source_time_text
                      ? ' (zona horaria sin verificar)'
                      : ''}
                    . Revisión de métrica: {sample.metric_revision}.
                  </p>
                  {sample.warnings.map((w) => (
                    <p
                      className={w.startsWith('Semántica pendiente') ? 'monitor-footnote' : 'error'}
                      key={w}
                    >
                      {w.startsWith('Semántica pendiente')
                        ? 'Datos leídos correctamente. Falta confirmar la unidad y escala; puedes contrastar el número original con la tabla pública que mostramos debajo.'
                        : w}
                    </p>
                  ))}
                  <label>
                    Ventana MRTG
                    <select value={window} onChange={(e) => setWindow(e.target.value)}>
                      {Object.entries(windows).map(([key, label]) => (
                        <option key={key} value={key}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Canal</th>
                          <th>Estadística</th>
                          <th>Valor extraído / convertido</th>
                          <th>Unidad / etiqueta</th>
                          <th>Tabla pública MRTG</th>
                          <th>Procedencia</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sample.values
                          .filter((p) => p.window === window)
                          .map((p) => (
                            <tr key={`${p.channel}-${p.statistic}`}>
                              <td>
                                {p.channel === 'in' ? 'Entrada' : 'Salida'}
                                {(p.display_label ||
                                  (p.label && !['in', 'out'].includes(p.label))) && (
                                  <small style={{ display: 'block' }}>
                                    {p.display_label || p.label}
                                  </small>
                                )}
                              </td>
                              <td>{statistics[p.statistic] ?? p.statistic}</td>
                              <td>
                                {(p.normalized_value ?? p.value).toLocaleString(undefined, {
                                  maximumSignificantDigits: 10,
                                })}
                              </td>
                              <td>
                                {p.unit ??
                                  (p.source_unit
                                    ? `${p.source_unit} (etiqueta de origen sin verificar)`
                                    : 'Unidad pendiente de confirmar')}
                              </td>
                              <td>
                                {p.display_value != null
                                  ? `${p.display_value.toLocaleString(undefined, { maximumSignificantDigits: 10 })} ${p.display_unit || ''}`
                                  : p.source === 'table'
                                    ? `${p.value.toLocaleString()} ${p.source_unit || ''}`
                                    : 'No publicada para esta estadística'}
                              </td>
                              <td>
                                {p.source === 'comment' ? 'Comentario MRTG' : 'Tabla visible'}
                                {p.normalized_value != null && (
                                  <small style={{ display: 'block' }}>
                                    Original: {p.value.toLocaleString()} · factor{' '}
                                    {sample.configuration.factor ?? 1}
                                  </small>
                                )}
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                  <p>
                    La columna «Tabla pública MRTG» reproduce su etiqueta, no confirma su
                    significado: algunas páginas conservan unidades heredadas como B/s para carga.
                    CPU puede publicar porcentajes superiores a 100; no se normalizan sin conocer su
                    base. Las ventanas son resúmenes de MRTG distintos. El valor «actual» semanal o
                    anual no equivale a una lectura instantánea.
                  </p>
                </>
              )}
            </>
          )}
        </>
      ) : (
        <p>
          El worker descubrirá las páginas del índice automáticamente. Mantén el servicio
          habilitado.
        </p>
      )}
    </section>
  );
}
