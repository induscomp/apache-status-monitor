import { useState } from 'react';
import type { FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api } from './api';

type Enrollment = { ticket: string; qr: string; manual_key: string; expires_in: number };

export function Setup({ done }: { done: () => void }) {
  const [token, setToken] = useState('');
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError('');
    if (!enrollment && data.get('password') !== data.get('confirmation')) {
      setError('Las contraseñas no coinciden.');
      return;
    }
    setBusy(true);
    try {
      if (!enrollment) {
        const key = String(data.get('token')).trim();
        const result = await api<Enrollment>('/setup/start', undefined, 'POST', {
          token: key,
          email: data.get('email'),
          password: data.get('password'),
        });
        form.reset();
        setToken(key);
        setEnrollment(result);
      } else {
        const result = await api<{ recovery_codes: string[] }>('/setup/finish', undefined, 'POST', {
          token,
          ticket: enrollment.ticket,
          code: data.get('code'),
        });
        setCodes(result.recovery_codes);
        setEnrollment(null);
        setToken('');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo completar la configuración.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="setup-layout">
      <section className="setup-card">
        <div className="square-icon">
          <ShieldCheck />
        </div>
        <span className="eyebrow">APACHE STATUS MONITOR · PRIMERA INSTALACIÓN</span>
        <p className="muted">Paso {codes.length ? 3 : enrollment ? 2 : 1} de 3</p>
        <h1>
          {codes.length
            ? 'Guarda tu acceso de recuperación'
            : enrollment
              ? 'Escanea y protege tu cuenta'
              : 'Configura tu panel'}
        </h1>
        {codes.length ? (
          <>
            <p>
              Tu administrador ya está creado y el asistente ha quedado cerrado. Guarda estos ocho
              códigos en tu gestor de contraseñas: cada uno permite entrar una sola vez si pierdes
              el autenticador.
            </p>
            <p>Se muestran únicamente ahora. Mantén esta pantalla abierta hasta guardarlos.</p>
            <ul className="recovery-codes">
              {codes.map((code) => (
                <li key={code}>
                  <code>{code}</code>
                </li>
              ))}
            </ul>
            <label className="checkbox">
              <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
              He guardado mis códigos de recuperación
            </label>
            <button
              className="primary wide"
              disabled={!saved}
              onClick={() => {
                setCodes([]);
                done();
              }}
            >
              Ir al inicio de sesión
            </button>
          </>
        ) : (
          <form onSubmit={submit} key={enrollment ? 'confirm' : 'account'}>
            {!enrollment ? (
              <>
                <p>
                  Crea tu cuenta de administrador. La clave de instalación acredita que esta
                  instalación te pertenece.
                </p>
                <label>
                  Clave de instalación
                  <input
                    name="token"
                    type="password"
                    autoComplete="off"
                    required
                    minLength={32}
                    maxLength={128}
                    aria-describedby="setup-key-help"
                  />
                </label>
                <p id="setup-key-help">
                  Abre el archivo <code>secrets/setup_token</code> en la carpeta del proyecto y
                  copia su contenido aquí. Se genera al preparar la instalación.
                </p>
                <label>
                  Email
                  <input
                    name="email"
                    type="email"
                    autoComplete="username"
                    required
                    maxLength={254}
                  />
                </label>
                <label>
                  Contraseña
                  <input
                    name="password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={14}
                    maxLength={1024}
                  />
                </label>
                <p>
                  Utiliza al menos 14 caracteres. En producción, el email debe coincidir con
                  Cloudflare Access.
                </p>
                <label>
                  Repite la contraseña
                  <input
                    name="confirmation"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={14}
                    maxLength={1024}
                  />
                </label>
              </>
            ) : (
              <>
                <p>
                  En tu aplicación autenticadora, selecciona añadir cuenta y escanear QR. Aparecerá
                  la cuenta Apache Status Monitor.
                </p>
                <img
                  className="setup-qr"
                  src={enrollment.qr}
                  alt="Código QR para configurar tu autenticador"
                />
                <details className="manual-key">
                  <summary>¿No puedes escanearlo?</summary>
                  <p>
                    Añade esta clave manualmente, tipo basado en tiempo (TOTP), seis dígitos y 30
                    segundos:
                  </p>
                  <code>{enrollment.manual_key}</code>
                </details>
                <label>
                  Código de seis dígitos
                  <input
                    name="code"
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    required
                    minLength={6}
                    maxLength={6}
                  />
                </label>
                <p>
                  Introduce el código que muestra el autenticador. Tienes diez minutos para
                  completar este paso. Si recargas la página, tendrás que empezar de nuevo.
                </p>
              </>
            )}
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <button className="primary wide" disabled={busy}>
              {busy
                ? 'Verificando…'
                : enrollment
                  ? 'Confirmar y crear administrador'
                  : 'Continuar al código QR'}
            </button>
            {enrollment && (
              <button
                type="button"
                className="secondary wide"
                disabled={busy}
                onClick={() => {
                  setEnrollment(null);
                  setToken('');
                  setError('');
                }}
              >
                Volver a empezar
              </button>
            )}
          </form>
        )}
      </section>
    </main>
  );
}
