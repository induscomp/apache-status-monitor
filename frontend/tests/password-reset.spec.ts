import { expect, test } from '@playwright/test';

test('password recovery explains factors, validates confirmation and returns to login', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  let submissions = 0;
  await page.route('**/api/v1/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/auth/session'))
      return route.fulfill({ status: 401, json: { detail: 'Inicia sesión' } });
    if (path.endsWith('/setup/status')) return route.fulfill({ json: { available: false } });
    if (path.endsWith('/auth/password-reset')) {
      if (route.request().method() === 'GET') return route.fulfill({ json: { available: true } });
      submissions++;
      const body = route.request().postDataJSON();
      expect(Object.keys(body).sort()).toEqual(['code', 'password']);
      expect(body.password).toBe('synthetic-new-password-2026');
      return submissions === 1
        ? route.fulfill({ status: 403, json: { detail: 'Código del monitor no válido.' } })
        : route.fulfill({ status: 204 });
    }
    return route.fulfill({ status: 404 });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'He olvidado mi contraseña' }).click();
  await expect(page.getByRole('heading', { name: 'Recuperar contraseña' })).toBeVisible();
  await page.getByLabel('Nueva contraseña', { exact: true }).fill('synthetic-new-password-2026');
  await page.getByLabel('Repite la nueva contraseña').fill('synthetic-other-password-2026');
  await page.getByLabel('Código del autenticador o de recuperación').fill('123456');
  await page.getByRole('button', { name: 'Guardar nueva contraseña' }).click();
  await expect(page.getByRole('alert')).toContainText('Las contraseñas no coinciden');
  expect(submissions).toBe(0);
  await page.getByLabel('Repite la nueva contraseña').fill('synthetic-new-password-2026');
  await page.getByRole('button', { name: 'Guardar nueva contraseña' }).click();
  await expect(page.getByRole('alert')).toContainText('Código del monitor no válido');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Guardar nueva contraseña' }).click();
  await expect(page.getByRole('heading', { name: 'Contraseña restablecida' })).toBeVisible();
  await expect(page.getByRole('status')).toContainText('cerrado todas las sesiones');
  await expect(page.locator('input[type=password]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Volver al inicio de sesión' }).click();
  await expect(page.getByRole('heading', { name: 'Bienvenido de nuevo' })).toBeVisible();
  expect(errors).toEqual([]);
});
