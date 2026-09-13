import { useEffect, useRef, useState } from 'react';
import { api, ApiError } from './api';

export function PasswordReset({ close }: { close: () => void }) {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
    let active = true;
    api<{ available: boolean }>('/auth/password-reset')
      .then((result) => {
        if (active) setAvailable(result.available);
      })
      .catch(() => {
        if (active)
          setError(
            'No se pudo comprobar tu identidad. Recarga la página y verifica tu acceso en Cloudflare.',
          );
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <section aria-label="Recuperar contraseña">
      <h2 ref={heading} tabIndex={-1}>
        {done ? 'Contraseña restablecida' : 'Recuperar contraseña'}
      </h2>
      {done ? (
        <>
          <p role="status">
            Se han cerrado todas las sesiones anteriores. Tu autenticador y tus datos se conservan.
          </p>
          <p>
            Entra con la nueva contraseña. Si has usado el autenticador, espera a que muestre un
            código nuevo. El código usado para recuperar el acceso no puede repetirse.
          </p>
        </>
      ) : (
        <>
          <p>
            Confirma tu identidad con el segundo factor de Apache Status Monitor y elige una
            contraseña nueva. Cloudflare debe haberte identificado con el mismo email de tu cuenta.
          </p>
          {available === null && !error && <p role="status">Comprobando tu acceso…</p>}
          {available === false && (
            <p role="status">
              Esta recuperación necesita Cloudflare Access con el email del administrador. Si estás
              en local o has entrado con otra cuenta, accede desde el dominio protegido con la
              cuenta correcta.
            </p>
          )}
          {available && (
            <form
              onSubmit={async (event) => {
                event.preventDefault();
                const form = event.currentTarget;
                const values = new FormData(form);
                if (values.get('password') !== values.get('confirmation')) {
                  setError('Las contraseñas no coinciden.');
                  return;
                }
                setBusy(true);
                setError('');
                try {
                  await api('/auth/password-reset', undefined, 'POST', {
                    password: values.get('password'),
                    code: values.get('code'),
                  });
                  form.reset();
                  setDone(true);
                  heading.current?.focus();
                } catch (error) {
                  setError(
                    error instanceof ApiError
                      ? error.message
                      : 'No se pudo completar la recuperación. Inténtalo de nuevo.',
                  );
                } finally {
                  setBusy(false);
                }
              }}
            >
              <label>
                Nueva contraseña
                <input
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={14}
                  maxLength={1024}
                  disabled={busy}
                />
              </label>
              <label>
                Repite la nueva contraseña
                <input
                  name="confirmation"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={14}
                  maxLength={1024}
                  disabled={busy}
                />
              </label>
              <p className="setup-help">
                Utiliza al menos 14 caracteres y guarda la contraseña en tu gestor.
              </p>
              <label>
                Código del autenticador o de recuperación
                <input
                  name="code"
                  autoComplete="one-time-code"
                  required
                  minLength={6}
                  maxLength={64}
                  spellCheck={false}
                  disabled={busy}
                />
              </label>
              <p className="setup-help">
                Son los seis dígitos de tu autenticador del monitor, o un código de recuperación
                guardado durante el alta. El código recibido por email de Cloudflare se utiliza solo
                en su pantalla de acceso.
              </p>
              <button className="primary wide" type="submit" disabled={busy}>
                {busy ? 'Restableciendo…' : 'Guardar nueva contraseña'}
              </button>
            </form>
          )}
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
        </>
      )}
      <button type="button" className="secondary wide" onClick={close} disabled={busy}>
        Volver al inicio de sesión
      </button>
    </section>
  );
}
