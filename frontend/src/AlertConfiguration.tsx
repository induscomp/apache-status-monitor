import { useEffect, useState } from 'react';
import { api } from './api';

type Settings = {
  domain_multiplier: number;
  domain_min_increase: number;
  memory_drop_percent: number;
  resource_multiplier: number;
  open_samples: number;
  recovery_samples: number;
};
const fields: {
  key: keyof Settings;
  label: string;
  min: number;
  max: number;
  step: number;
  help: string;
}[] = [
  {
    key: 'domain_multiplier',
    label: 'Multiplicador de actividad del dominio',
    min: 1.1,
    max: 100,
    step: 0.1,
    help: 'Por ejemplo, 3 exige al menos el triple de su actividad habitual.',
  },
  {
    key: 'domain_min_increase',
    label: 'Aumento mínimo de conexiones o apariciones',
    min: 1,
    max: 10000,
    step: 1,
    help: 'Se exige también una desviación significativa respecto a la variabilidad habitual.',
  },
  {
    key: 'memory_drop_percent',
    label: 'Caída de memoria libre respecto al histórico (%)',
    min: 1,
    max: 99,
    step: 1,
    help: '50 avisa cuando queda la mitad o menos de la memoria libre habitual.',
  },
  {
    key: 'resource_multiplier',
    label: 'Multiplicador de CPU y carga',
    min: 1.1,
    max: 100,
    step: 0.1,
    help: 'Se compara cada recurso con su propia referencia, en la misma escala.',
  },
  {
    key: 'open_samples',
    label: 'Muestras para abrir un aviso',
    min: 2,
    max: 12,
    step: 1,
    help: 'Muestras significativas consecutivas, recogidas cada 5 minutos.',
  },
  {
    key: 'recovery_samples',
    label: 'Muestras para resolver un aviso',
    min: 2,
    max: 12,
    step: 1,
    help: 'Muestras recuperadas consecutivas. La falta de datos nunca resuelve un aviso.',
  },
];
export function AlertConfiguration({ serverId, csrf }: { serverId: string; csrf: string }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api<Settings>(`/servers/${serverId}/alert-settings`)
      .then((value) => {
        if (active) setSettings(value);
      })
      .catch(() => {
        if (active) setMessage('No se pudieron cargar los ajustes de alertas.');
      });
    return () => {
      active = false;
    };
  }, [serverId]);
  return (
    <section className="incident-summary" aria-label="Configuración de alertas">
      <h2>Alertas de este servidor</h2>
      <p>
        Estos valores se aplican a sus servicios Apache y MRTG. Se mantiene la comparación con el
        histórico de 24 horas y se excluyen los últimos 30 minutos. GoAccess muestra la frescura de
        su informe.
      </p>
      {settings && (
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setMessage('');
            try {
              setSettings(
                await api<Settings>(`/servers/${serverId}/alert-settings`, csrf, 'PUT', settings),
              );
              setMessage(
                'Ajustes guardados. Se aplicarán a las próximas evaluaciones; el histórico se conserva.',
              );
            } catch {
              setMessage(
                'No se pudieron guardar los ajustes. Revisa los valores e inténtalo de nuevo.',
              );
            } finally {
              setBusy(false);
            }
          }}
        >
          <fieldset disabled={busy} className="alert-settings-fields">
            {fields.map((field) => (
              <label key={field.key}>
                {field.label}
                <input
                  type="number"
                  required
                  min={field.min}
                  max={field.max}
                  step={field.step}
                  value={settings[field.key]}
                  onChange={(event) =>
                    setSettings({ ...settings, [field.key]: event.target.valueAsNumber })
                  }
                />
                <small>{field.help}</small>
              </label>
            ))}
          </fieldset>
          <p>
            RAM en naranja; memoria en rojo solo con uso de swap confirmado. Configura la capacidad
            total de swap en su métrica MRTG para poder comprobarlo.
          </p>
          <button type="submit" disabled={busy}>
            {busy ? 'Guardando…' : 'Guardar ajustes de alertas'}
          </button>
        </form>
      )}
      <p role="status">{message}</p>
    </section>
  );
}
