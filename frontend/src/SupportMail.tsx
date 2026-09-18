import { useEffect, useState } from 'react';
import { api } from './api';

type Delivery = { id: string; status: string; created_at: string; error?: string | null };
type Draft = Delivery & { recipient: string; subject: string; body: string; ips: string[] };
const statusText: Record<string, string> = {
  draft: 'Borrador sin enviar',
  sending: 'Envío iniciado; no repetir',
  sent: 'Aceptado por el servidor SMTP',
  uncertain: 'Entrega sin confirmar; no se reintentará',
};
export function SupportMail({ serverId, csrf }: { serverId: string; csrf: string }) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [settings, setSettings] = useState<{
    email: string;
    ready: boolean;
    reports: Delivery[];
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    void api<{ email: string; ready: boolean; reports: Delivery[] }>(`/servers/${serverId}/support`)
      .then((value) => {
        if (live) setSettings(value);
      })
      .catch((e) => {
        if (live) setError(e.message);
      });
    return () => {
      live = false;
    };
  }, [serverId]);
  async function prepare() {
    setBusy(true);
    setError('');
    try {
      setDraft(await api<Draft>(`/servers/${serverId}/support/drafts`, csrf, 'POST'));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function send() {
    if (!draft) return;
    setBusy(true);
    setError('');
    try {
      const result = await api<Delivery>(
        `/servers/${serverId}/support/${draft.id}/send`,
        csrf,
        'POST',
      );
      setDraft({ ...draft, ...result });
      if (result.error) setError(result.error);
      setSettings(await api(`/servers/${serverId}/support`));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section aria-label="Correo con IP candidatas" className="overview-card">
      <strong>Correo con IP candidatas</strong>
      <p>
        Destino: {settings?.email || 'Configúralo en Correo'}. Las alertas automáticas y estas
        solicitudes usan el destinatario de la aplicación.
      </p>
      {settings && !settings.ready && (
        <p>
          El SMTP está desactivado o sin verificar. En Correo, guarda el destinatario, comprueba el
          envío y activa los avisos.
        </p>
      )}
      <button type="button" disabled={busy || !settings?.email} onClick={() => void prepare()}>
        {busy ? 'Procesando…' : 'Preparar correo con las IP'}
      </button>
      <small>
        {' '}
        Se prepara con las campañas recientes de la última hora. No envía hasta que revises y
        confirmes.
      </small>
      {error && <p role="alert">{error}</p>}
      {draft && (
        <div>
          <h4>Revisa el correo antes de enviarlo</h4>
          <p>
            Para: <strong>{draft.recipient}</strong> · {draft.ips.length} IP candidatas
          </p>
          <p>Asunto: {draft.subject}</p>
          <textarea
            aria-label="Vista previa del correo"
            readOnly
            rows={12}
            value={draft.body}
            style={{ width: '100%' }}
          />
          <p role="status">{statusText[draft.status] || draft.status}</p>
          <button
            type="button"
            disabled={busy || !settings?.ready || draft.status !== 'draft'}
            onClick={() => void send()}
          >
            Confirmar y enviar este correo
          </button>
          <p>
            El borrador caduca a los 15 minutos. Una aceptación SMTP no confirma lectura ni bloqueo
            de IP.
          </p>
        </div>
      )}
      {!!settings?.reports?.length && (
        <details>
          <summary>Últimas solicitudes · 30 días</summary>
          {settings.reports.map((r) => (
            <p key={r.id}>
              {new Date(r.created_at).toLocaleString('es')} · {statusText[r.status] || r.status}
            </p>
          ))}
        </details>
      )}
    </section>
  );
}
