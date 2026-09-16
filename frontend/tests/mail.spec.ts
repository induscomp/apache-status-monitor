import { expect, test } from '@playwright/test';

test('mail requires a saved successful test before enabling alerts', async ({ page }) => {
  let config = {
    enabled: false,
    host: 'smtp.example.test',
    port: 465,
    security: 'tls',
    username: 'user',
    sender: 'from@example.test',
    recipient: 'to@example.test',
    has_password: true,
    verified_at: null as string | null,
  };
  let tests = 0;
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = {};
    if (path.endsWith('/auth/session'))
      json = { email: 'admin@example.test', csrf_token: 'synthetic' };
    else if (path.endsWith('/dashboard')) json = { items: [], total: 0, open_incidents: 0 };
    else if (path.endsWith('/servers')) json = { items: [], total: 0 };
    else if (path.endsWith('/notifications/test')) {
      tests++;
      config.verified_at = new Date().toISOString();
      json = { ok: true, message: 'El servidor SMTP ha aceptado el correo de prueba.' };
    } else if (path.endsWith('/notifications')) {
      if (route.request().method() === 'PUT')
        config = { ...config, ...route.request().postDataJSON() };
      json = config;
    }
    await route.fulfill({ json });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Correo de la cuenta', exact: true }).click();
  const enable = page.getByLabel('Activar avisos por email');
  await expect(enable).toBeDisabled();
  await page.getByRole('button', { name: 'Comprobar y enviar prueba' }).click();
  await expect(page.getByRole('status')).toContainText('aceptado');
  await expect(enable).toBeEnabled();
  await expect(enable).not.toBeChecked();
  await enable.check();
  await page.getByRole('button', { name: 'Guardar correo', exact: true }).click();
  await expect(page.getByText('Avisos activados.', { exact: false })).toBeVisible();
  expect(config.enabled).toBe(true);
  await page.getByLabel('Destinatario', { exact: true }).fill('other@example.test');
  await expect(enable).toBeDisabled();
  await expect(enable).not.toBeChecked();
  await expect(page.getByRole('button', { name: 'Comprobar y enviar prueba' })).toBeDisabled();
  expect(tests).toBe(1);
});
