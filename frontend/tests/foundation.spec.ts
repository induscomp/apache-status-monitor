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

  await expect(page.getByRole('heading', { name: 'Mis servidores', exact: true })).toBeVisible();

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
    if (kind === 'mrtg')
      await page.getByLabel('Permitir HTTP sin cifrado', { exact: false }).check();
    await page.getByRole('button', { name: 'Guardar servicio' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: name })).toBeVisible();
  }
  await server('Atlas · Producción');
  await service('Apache principal', 'apache_status');
  const overviewAt = new Date().toISOString();
  const ram = {
    value: 20,
    unit: 'valor de origen',
    provenance: 'Memoria Física Libre / out',
    observed_at: overviewAt,
    source_at: null,
  };
  await page.route('**/api/v1/servers/*/analysis?*', (route) =>
    route.fulfill({
      json: {
        incident_summary: {
          start: overviewAt,
          end: overviewAt,
          partial: false,
          open: 1,
          critical: 1,
          resolved: 0,
          bins: [
            {
              start: overviewAt,
              end: overviewAt,
              state: 'critical',
              coverage: 'partial',
              samples: 2,
              incidents: 1,
              resolved: 0,
              details: [
                {
                  subject: 'domain:example.test',
                  service: 'Apache principal',
                  opened_at: overviewAt,
                  resolved_at: null,
                  severity: 'critical',
                },
              ],
            },
          ],
        },
        state: 'resource_pressure',
        service_id: 'fixture-service',
        services: [{ id: 'fixture-service', name: 'Apache principal' }],
        last_at: overviewAt,
        learning: { valid_baseline_samples: 180, required_samples: 170 },
        series: [
          {
            at: overviewAt,
            ram_free: 20,
            free_slots: 900,
            domain_active: 20,
            domain_appearances: 22,
          },
        ],
        metrics: { free_slots: 900 },
        resources: { ram_free: ram },
        domains: [{ domain: 'example.test', active: 20, appearances: 22 }],
        period_rankings: [{ domain: 'example.test', appearances: 300 }],
        rankings: {
          ips: [{ ip: '2001:db8::1', count: 20, country: null, asn: null }],
          posts: [{ domain: 'example.test', ip: '2001:db8::1', path: '/wp-login.php', count: 5 }],
        },
        warnings: ['Zona horaria sin verificar'],
        open_incidents: 1,
        limitation: 'Slots libres no prueban salud.',
        geoip: { country: false, asn: false },
      },
    }),
  );
  await page.route('**/api/v1/servers/*/incidents?*', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: 'incident-1',
            subject: 'resource:ram_free',
            status: 'open',
            severity: 'critical',
            opened_at: overviewAt,
            updated_at: overviewAt,
            evidence: {
              value: 20,
              reference: { median: 100, mad: 0, samples: 12 },
              note: 'Coincidencia temporal; no demuestra causalidad.',
              feature: 'ram_free',
              resources: { ram_free: ram },
              coincidences: {},
              domains: [{ domain: 'example.test', active: 20 }],
            },
          },
        ],
      },
    }),
  );
  await page.getByRole('button', { name: 'Estado del servidor', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Presión de recursos detectada' })).toBeVisible();
  await expect(page.getByText('Slots libres no prueban salud.', { exact: true })).toBeVisible();
  const timeSegment = page
    .getByRole('region', { name: 'Resumen temporal de incidencias' })
    .locator('.incident-segment')
    .first();
  await timeSegment.hover();
  await expect(page.getByRole('tooltip')).toContainText('Dominio: example.test');
  await expect(page.getByRole('tooltip')).toContainText('Cobertura parcial');
  await timeSegment.focus();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  await page.getByRole('button', { name: 'Gráficos y rankings', exact: true }).click();
  await page.getByRole('button', { name: 'example.test', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'Histórico de example.test' })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    .toBe(true);
  await timeSegment.click();
  await expect(page.getByRole('tooltip')).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('server-status-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Incidentes', exact: true }).click();
  await expect(page.getByText('Coincidencia temporal; no demuestra causalidad.')).toBeVisible();
  await page.getByText('Ver evidencias coincidentes', { exact: true }).click();
  await expect(page.getByText('example.test: 20 workers activos observados')).toBeVisible();
  await page.getByRole('button', { name: 'Correo', exact: true }).click();
  await expect(page.getByLabel('Activar avisos por email')).not.toBeChecked();
  await page.getByRole('button', { name: 'Configuración', exact: true }).click();
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
  await page.getByRole('button', { name: 'Configuración', exact: true }).click();
  await expect(page.getByRole('row')).toHaveCount(4);
  await page.reload();
  await page.getByRole('button', { name: 'Atlas · Producción', exact: true }).click();
  await page.getByRole('button', { name: 'Configuración', exact: true }).click();
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
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Inicio', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Mis servidores', exact: true })).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Ver servidor Boreal · Staging', exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Configurar correo de la cuenta', exact: true }).click();
  await expect(page.getByLabel('Destinatario', { exact: true })).toHaveValue('admin@example.test');
  await page.getByLabel('Seguridad SMTP').selectOption('starttls');
  await expect(page.getByLabel('Puerto TLS', { exact: true })).toHaveValue('587');
  await page.unroute('**/api/v1/servers/*/analysis?*');
  await server('Informe público');
  await page.getByRole('button', { name: 'Añadir servicio', exact: true }).click();
  await page.getByLabel('Tipo de servicio').selectOption('goaccess');
  await page.getByLabel('Nombre del servicio').fill('Informe GoAccess');
  await page
    .getByLabel('URL del informe GoAccess')
    .fill('https://another.example.test/report.html');
  await page.getByRole('button', { name: 'Guardar servicio' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Estado del servidor', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Resumen de las fuentes disponibles' }),
  ).toBeVisible();
  await expect(page.getByLabel('Servicio Apache', { exact: true })).toHaveCount(0);
  await page.route('**/api/v1/services/*/goaccess', (route) =>
    route.fulfill({
      json: {
        status: 'stale',
        checked_at: overviewAt,
        warnings: ['Informe desactualizado'],
        note: 'No describe el estado actual.',
        history: [],
        report: {
          generated_at: '2026-03-13T03:00:03Z',
          observed_at: overviewAt,
          summary: { valid_requests: 245684 },
          panels: {
            vhosts: [
              { label: '<img src=x onerror=alert(1)>', hits: 3, visitors: 2, bytes: 8, method: '' },
            ],
          },
        },
      },
    }),
  );
  await page.getByRole('button', { name: 'Ver detalle de Informe GoAccess', exact: true }).click();
  const goaccessDialog = page.getByRole('dialog');
  await expect(
    goaccessDialog.getByRole('heading', { name: 'GoAccess · Desactualizado' }),
  ).toBeVisible();
  await goaccessDialog
    .getByText('Dominios del informe (1 filas disponibles)', { exact: true })
    .click();
  await expect(
    goaccessDialog.getByText('<img src=x onerror=alert(1)>', { exact: true }),
  ).toBeVisible();
  await expect(goaccessDialog.locator('img')).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('goaccess-mobile.png'), fullPage: true });
  await goaccessDialog.getByLabel('Cerrar', { exact: true }).click();
  await page.getByRole('button', { name: 'Cerrar sesión', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Bienvenido de nuevo' })).toBeVisible();
  expect((await page.request.get('/api/v1/servers')).status()).toBe(401);
  expect(errors).toEqual([]);
});
