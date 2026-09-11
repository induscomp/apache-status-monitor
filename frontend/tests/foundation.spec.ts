import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';

function currentCode(secret: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...secret]
    .map((letter) => alphabet.indexOf(letter).toString(2).padStart(5, '0'))
    .join('');
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', key).update(counter).digest();
  const offset = hash[hash.length - 1] & 15;
  return ((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}

test('administrator configures independent services, persists changes and revokes access', async ({
  page,
}, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Configura tu panel' })).toBeVisible();
  await page
    .getByLabel('Clave de instalación', { exact: true })
    .fill(readFileSync(process.env.SMON_SETUP_TOKEN_FILE!, 'utf8').trim());
  await page.getByLabel('Email', { exact: true }).fill('admin@example.test');
  await page.getByLabel('Contraseña', { exact: true }).fill(process.env.SMON_E2E_PASSWORD!);
  await page
    .getByLabel('Repite la contraseña', { exact: true })
    .fill(process.env.SMON_E2E_PASSWORD!);
  await page.getByRole('button', { name: 'Continuar al código QR' }).click();
  await expect(
    page.getByRole('img', { name: 'Código QR para configurar tu autenticador' }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('setup-qr.png'), fullPage: true });
  await page.getByText('¿No puedes escanearlo?', { exact: true }).click();
  const secret = await page.locator('.manual-key code').innerText();
  await page.getByLabel('Código de seis dígitos', { exact: true }).fill(currentCode(secret));
  await page.getByRole('button', { name: 'Confirmar y crear administrador' }).click();
  await expect(
    page.getByRole('heading', { name: 'Guarda tu acceso de recuperación' }),
  ).toBeVisible();
  await expect(page.locator('.recovery-codes li')).toHaveCount(8);
  const recovery = await page.locator('.recovery-codes code').first().innerText();
  await expect(page.getByRole('button', { name: 'Ir al inicio de sesión' })).toBeDisabled();
  await page.getByLabel('He guardado mis códigos de recuperación').check();
  await page.getByRole('button', { name: 'Ir al inicio de sesión' }).click();
  await page.reload();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await expect(page.getByRole('heading', { name: 'Bienvenido de nuevo' })).toBeVisible();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.test');
  await page.getByLabel('Contraseña', { exact: true }).fill(process.env.SMON_E2E_PASSWORD!);
  await page.getByLabel('Código de autenticación o recuperación').fill(recovery);
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
        page.getByText('MRTG se lee siguiendo los enlaces', { exact: false }),
      ).toBeVisible();
    await page.getByRole('button', { name: 'Guardar servicio' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: name })).toBeVisible();
  }
  await server('Atlas · Producción');
  await service('Apache principal', 'apache_status');
  await page.getByRole('button', { name: 'Ver diagnóstico', exact: true }).click();
  await expect(page.getByText('Aún no hay muestras.', { exact: false })).toBeVisible();
  await page.getByRole('dialog').getByLabel('Cerrar', { exact: true }).click();
  const sample = {
    id: 'fixture',
    service_id: 'fixture-service',
    revision: 1,
    observed_at: '2026-09-11T12:00:00Z',
    status: 'ok',
    warnings: [],
    metrics: { observed_workers: 1, active_workers: 1, global: { BusyWorkers: 1, IdleWorkers: 4 } },
  };
  await page.route('**/api/v1/services/*/observations', (route) =>
    route.fulfill({ json: { items: [sample] } }),
  );
  await page.route('**/api/v1/observations/fixture?offset=0', (route) =>
    route.fulfill({
      json: {
        ...sample,
        total_workers: 1,
        details_expired: false,
        workers: [
          {
            slot: '1-0',
            state: 'W',
            client: '2001:db8::1',
            domain: 'example.test',
            method: 'GET',
            path: '/page',
            seconds_since: 2,
            request_ms: 50,
            observation: 'current',
          },
        ],
      },
    }),
  );
  await page.getByRole('button', { name: 'Ver diagnóstico', exact: true }).click();
  await expect(page.getByRole('dialog').getByText('2001:db8::1', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog').getByText('GET /page', { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath('apache-diagnostic-mobile.png'),
    fullPage: true,
  });
  await page.getByRole('dialog').getByLabel('Cerrar', { exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.unroute('**/api/v1/services/*/observations');
  await page.unroute('**/api/v1/observations/fixture?offset=0');
  await service('Apache secundario', 'apache_status');
  await service('Estadísticas del sistema', 'mrtg');
  const mrtgSample = {
    id: 'mrtg-sample',
    observed_at: '2026-09-11T12:00:00Z',
    source_at: null,
    source_time_text: 'Friday, 11 September 2026 at 14:00',
    status: 'partial',
    metric_revision: 1,
    configuration: {},
    warnings: ['Semántica pendiente de interpretación.'],
    values: [
      {
        window: 'd',
        channel: 'in',
        statistic: 'current',
        value: 500,
        source: 'comment',
        source_unit: null,
      },
      {
        window: 'w',
        channel: 'in',
        statistic: 'average',
        value: 300,
        source: 'comment',
        source_unit: null,
      },
    ],
  };
  await page.route('**/api/v1/services/*/mrtg', (route) =>
    route.fulfill({
      json: {
        discovery: {
          attempted_at: '2026-09-11T12:00:00Z',
          succeeded_at: '2026-09-11T12:00:00Z',
          requested: false,
          error: null,
        },
        items: [
          {
            id: 'mrtg-fixture',
            name: 'Carga del sistema',
            url: 'http://metrics.example.test/mrtg/load.html',
            selected: true,
            present: true,
            revision: 1,
            configuration: {},
            latest: mrtgSample,
          },
        ],
      },
    }),
  );
  await page.route('**/api/v1/mrtg/metrics/mrtg-fixture/observations', (route) =>
    route.fulfill({ json: { items: [mrtgSample] } }),
  );
  let savedMetric: { selected: boolean; factor: number } | undefined;
  await page.route('**/api/v1/mrtg/metrics/mrtg-fixture', (route) => {
    savedMetric = route.request().postDataJSON();
    return route.fulfill({ json: { revision: 2 } });
  });
  await page
    .getByRole('row')
    .filter({ hasText: 'Estadísticas del sistema' })
    .getByRole('button', { name: 'Ver diagnóstico' })
    .click();
  const mrtgDialog = page.getByRole('dialog');
  await expect(mrtgDialog.getByText('500', { exact: true })).toBeVisible();
  await mrtgDialog.getByLabel('Ventana MRTG').selectOption('w');
  await expect(mrtgDialog.getByText('300', { exact: true })).toBeVisible();
  await expect(mrtgDialog.getByText('500', { exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('mrtg-mobile.png'), fullPage: true });
  await mrtgDialog.getByLabel('Monitorizar esta página').uncheck();
  await mrtgDialog.getByRole('button', { name: 'Guardar métrica', exact: true }).click();
  await expect(mrtgDialog.getByRole('status')).toContainText('Configuración guardada');
  expect(savedMetric?.selected).toBe(false);
  expect(savedMetric?.factor).toBe(1);
  await mrtgDialog.getByLabel('Cerrar', { exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.unroute('**/api/v1/services/*/mrtg');
  await page.unroute('**/api/v1/mrtg/metrics/mrtg-fixture/observations');
  await page.unroute('**/api/v1/mrtg/metrics/mrtg-fixture');
  const apache = page.getByRole('row').filter({ hasText: 'Apache principal' });
  await apache.getByLabel('Acciones de Apache principal').click();
  await apache.getByRole('button', { name: 'Pausar', exact: true }).click();
  await expect(apache.getByText('Pausado', { exact: true })).toBeVisible();
  await expect(
    page
      .getByRole('row')
      .filter({ hasText: 'Estadísticas del sistema' })
      .getByText('Esperando primera recogida'),
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
