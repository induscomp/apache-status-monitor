import { expect, test } from '@playwright/test';

test('administrator configures independent services, persists changes and revokes access', async ({
  page,
}, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Bienvenido de nuevo' })).toBeVisible();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.test');
  await page.getByLabel('Contraseña', { exact: true }).fill(process.env.SMON_E2E_PASSWORD!);
  await page.getByLabel('Código de autenticación o recuperación').fill('e2e-recovery-fixture');
  await page.getByRole('button', { name: 'Entrar al panel' }).click();
  await expect(page.getByRole('heading', { name: 'Tu infraestructura' })).toBeVisible();

  async function server(name: string) {
    await page.getByRole('button', { name: 'Añadir servidor', exact: true }).last().click();
    await page.getByLabel('Nombre del servidor').fill(name);
    await page.getByLabel('Descripción', { exact: true }).fill('Infraestructura web · Frankfurt');
    await page.getByLabel('Etiquetas').fill('producción, web');
    await page.getByRole('button', { name: 'Guardar servidor' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  }
  async function service(name: string, kind: 'apache_status' | 'mrtg') {
    await page.getByRole('button', { name: 'Añadir servicio', exact: true }).click();
    await page.getByLabel('Tipo de servicio').selectOption(kind);
    await page.getByLabel('Nombre del servicio').fill(name);
    await page
      .getByLabel(kind === 'mrtg' ? 'URL del índice MRTG' : 'URL base de Apache Status')
      .fill(
        kind === 'mrtg'
          ? 'http://metrics.example.test/mrtg/'
          : 'https://web.example.test/server-status',
      );
    if (kind === 'mrtg')
      await expect(
        page.getByText('MRTG se leerá siguiendo los enlaces', { exact: false }),
      ).toBeVisible();
    await page.getByRole('button', { name: 'Guardar servicio' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: name })).toBeVisible();
  }
  await server('Atlas · Producción');
  await service('Apache principal', 'apache_status');
  await service('Apache secundario', 'apache_status');
  await service('Estadísticas del sistema', 'mrtg');
  const apache = page.getByRole('row').filter({ hasText: 'Apache principal' });
  await apache.getByLabel('Acciones de Apache principal').click();
  await apache.getByRole('button', { name: 'Pausar', exact: true }).click();
  await expect(apache.getByText('Pausado', { exact: true })).toBeVisible();
  await expect(
    page
      .getByRole('row')
      .filter({ hasText: 'Estadísticas del sistema' })
      .getByText('Pendiente de recolector'),
  ).toBeVisible();

  await server('Boreal · Staging');
  await service('Apache principal', 'apache_status');
  await expect(page.getByRole('row')).toHaveCount(2);
  await page.getByRole('button', { name: 'Atlas · Producción', exact: true }).click();
  await expect(page.getByRole('row')).toHaveCount(4);
  await page.reload();
  await expect(
    page
      .getByRole('row')
      .filter({ hasText: 'Apache principal' })
      .getByText('Pausado', { exact: true }),
  ).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('desktop.png'), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: 'Tu infraestructura' })).toBeVisible();
  const noPageOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth,
  );
  await page.screenshot({ path: testInfo.outputPath('mobile.png'), fullPage: true });
  if (!noPageOverflow) {
    console.log(
      await page.evaluate(() => ({
        width: innerWidth,
        actual: document.documentElement.scrollWidth,
        elements: [...document.querySelectorAll('body *')]
          .filter((e) => e.getBoundingClientRect().right > innerWidth + 1 && !e.closest('table'))
          .slice(0, 15)
          .map((e) => ({
            tag: e.tagName,
            cls: e.className,
            right: e.getBoundingClientRect().right,
          })),
      })),
    );
  }
  expect(noPageOverflow).toBe(true);
  await page.getByRole('button', { name: 'Cerrar sesión', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Bienvenido de nuevo' })).toBeVisible();
  expect((await page.request.get('/api/v1/servers')).status()).toBe(401);
  expect(errors).toEqual([]);
});
