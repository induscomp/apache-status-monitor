import { expect, test } from '@playwright/test';

test('server monitors show resources and activity instead of collection sources', async ({
  page,
}, testInfo) => {
  const at = new Date().toISOString();
  let supportSends = 0;
  const rows = [
    {
      id: 'latency',
      name: 'Latencia / tiempo de respuesta',
      state: 'learning',
      status_text: 'Aprendiendo latencia',
      display_bytes: null,
      value: 150,
      unit: 'ms',
      value_label: 'media global entre muestras',
    },
    {
      id: 'ram_free',
      name: 'Memoria RAM',
      state: 'warning',
      status_text: 'Aviso abierto',
      display_bytes: 2.22e9,
      value: 2220000,
      unit: 'bytes',
      value_label: 'libres',
    },
    {
      id: 'swap_free',
      name: 'Swap',
      state: 'unknown',
      status_text: 'Uso sin determinar',
      display_bytes: 66e9,
      value: 66000000,
      unit: 'bytes',
      value_label: 'libres',
    },
    {
      id: 'cpu',
      name: 'CPU',
      state: 'observed',
      status_text: 'Dentro de lo habitual',
      display_bytes: null,
      value: 15,
      unit: '%',
      value_label: '',
    },
    {
      id: 'load',
      name: 'Carga del servidor',
      state: 'observed',
      status_text: 'Dentro de lo habitual',
      display_bytes: null,
      value: 2.25,
      unit: 'carga',
      value_label: '',
    },
    {
      id: 'domains',
      name: 'Actividad por dominio',
      state: 'observed',
      status_text: 'Sin anomalías de dominio',
      display_bytes: null,
      value: 4,
      unit: 'conexiones',
      value_label: 'máximo por dominio',
    },
    {
      id: 'ips',
      name: 'Conexiones por IP',
      state: 'informational',
      status_text: 'Observación',
      display_bytes: null,
      value: 3,
      unit: 'conexiones',
      value_label: 'máximo por IP',
    },
  ].map((row) => ({
    ...row,
    ranking:
      row.id === 'domains'
        ? [
            {
              domain: 'example.test',
              service: 'Apache A',
              service_id: 'a',
              average: 2,
              current: 4,
              peak: 8,
              bins: Array.from({ length: 48 }, (_, i) => ({
                start: at,
                value: i < 10 ? null : i % 5,
                samples: i < 10 ? 0 : 6,
              })),
            },
          ]
        : [],
    latest_at: at,
    reason:
      row.id === 'ips'
        ? 'La concentración no demuestra un ataque.'
        : 'Estado de este indicador, independiente de otras métricas.',
    action: row.id === 'ips' ? 'ips' : 'resources',
    context:
      row.id === 'ips' ? [{ label: '192.0.2.1', text: '3 conexiones · Proveedor de prueba' }] : [],
    bins: Array.from({ length: 48 }, (_, index) => ({
      start: new Date(Date.now() - (48 - index) * 1800000).toISOString(),
      end: new Date(Date.now() - (47 - index) * 1800000).toISOString(),
      state: row.state,
      coverage: row.state === 'unknown' ? 'missing' : 'complete',
      samples: 6,
      incidents: row.state === 'warning' ? 1 : 0,
      resolved: 0,
      details: [],
    })),
  }));
  const server = {
    id: 'server',
    name: 'Servidor de prueba',
    description: '',
    tags: [],
    archived: false,
  };
  await page.route('**/api/v1/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = {};
    if (path.endsWith('/auth/session'))
      json = { email: 'admin@example.test', csrf_token: 'synthetic' };
    else if (path.endsWith('/dashboard'))
      json = {
        items: [{ ...server, state: 'incident', open_incidents: 1, sources: [] }],
        total: 1,
        open_incidents: 1,
      };
    else if (path.endsWith('/servers')) json = { items: [server], total: 1 };
    else if (path.endsWith('/services')) json = { items: [], total: 0 };
    else if (path.endsWith('/incidents')) json = { items: [] };
    else if (path.endsWith('/security-analysis'))
      json = {
        state: 'Vigilancia',
        items: [],
        series: [],
        endpoints: [],
        active_ips: [],
        active_domains: [],
      };
    else if (path.endsWith('/support'))
      json = { email: 'owner@example.test', ready: true, reports: [] };
    else if (path.endsWith('/support/drafts'))
      json = {
        id: 'draft',
        status: 'draft',
        created_at: at,
        recipient: 'owner@example.test',
        subject: 'Solicitud de bloqueo',
        body: '192.0.2.1 · example.test · POST /wp-login.php',
        ips: ['192.0.2.1'],
      };
    else if (path.endsWith('/support/draft/send')) {
      supportSends++;
      json = { id: 'draft', status: 'sent', created_at: at };
    } else if (path.endsWith('/ip-activity')) {
      const row = {
        key: '192.0.2.1',
        score: 60,
        flagged: true,
        status: 'Patrón para revisar',
        observations: 4,
        peak: 2,
        samples: 2,
        first: at,
        last: at,
        retained: 1,
        signatures: 3,
        probes: 2,
        reasons: ['Sondeo de configuración'],
        ips: ['192.0.2.1', '192.0.2.2'],
        domains: ['example.test'],
        endpoints: { 'GET /.env': 2 },
        shared: [{ target: 'example.test · GET /.env', ips: ['192.0.2.1', '192.0.2.2'] }],
        reference: null,
        geo: null,
      };
      json = {
        items: [
          {
            service: 'Apache',
            service_id: 'apache',
            fresh: true,
            coverage: 1,
            samples: 6,
            expected: 6,
            start: at,
            end: at,
            ips: [row],
            networks: [
              {
                ...row,
                key: '192.0.2.0/24',
                high_priority: true,
                support_ips: ['192.0.2.1', '192.0.2.2'],
                support_evidence: [
                  {
                    ip: '192.0.2.1',
                    domain: 'one.test',
                    endpoint: 'GET /.env',
                    captures: [at],
                    geo: { country: 'VN', asn: 64500, organization: 'Test network' },
                  },
                  {
                    ip: '192.0.2.2',
                    domain: 'two.test',
                    endpoint: 'POST /wp-login.php',
                    captures: [at],
                    geo: null,
                  },
                ],
              },
            ],
          },
        ],
      };
    } else if (path.endsWith('/analysis'))
      json = {
        server: server.name,
        state: 'resource_pressure',
        has_apache: true,
        sources: [],
        services: [],
        last_at: at,
        learning: { valid_baseline_samples: 180, required_samples: 170 },
        series: [],
        resources: {},
        metrics: {},
        domains: [],
        period_rankings: [],
        rankings: {},
        warnings: [],
        open_incidents: 1,
        geoip: { country: true, asn: true },
        incident_summary: {
          start: at,
          end: at,
          partial: false,
          open: 1,
          critical: 0,
          resolved: 0,
          bins: [],
          monitors: rows,
        },
      };
    return route.fulfill({ json });
  });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Ver servidor Servidor de prueba', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Seguridad y anomalías' })).toContainText(
    'Estado general: Vigilancia',
  );
  const campaigns = page.getByRole('region', { name: 'Alertas importantes de IP' });
  await expect(campaigns).toContainText('Prioridad alta');
  await expect(campaigns).toContainText('Vietnam');
  await campaigns.getByText('1 grupos · 2 IP candidatas · listado completo para soporte').click();
  await expect(campaigns.getByLabel('Informe completo para soporte')).toHaveValue(/192\.0\.2\.2/);
  const fullDownload = page.waitForEvent('download');
  await campaigns.getByRole('button', { name: 'Descargar informe completo', exact: true }).click();
  expect((await fullDownload).suggestedFilename()).toBe('informe-ips-soporte.txt');
  await campaigns.getByText('2 IP candidatas a bloqueo · evidencias para soporte').click();
  await expect(campaigns.getByLabel('Informe para soporte')).toHaveValue(/192\.0\.2\.1/);
  await expect(campaigns.getByLabel('Informe para soporte')).toHaveValue(/one\.test/);
  const download = page.waitForEvent('download');
  await campaigns.getByRole('button', { name: 'Descargar informe', exact: true }).click();
  expect((await download).suggestedFilename()).toBe('informe-ips-soporte.txt');
  const support = page.getByRole('region', { name: 'Correo con IP candidatas' });
  await support.getByRole('button', { name: 'Preparar correo con las IP' }).click();
  await expect(support.getByLabel('Vista previa del correo')).toHaveValue(/192\.0\.2\.1/);
  expect(supportSends).toBe(0);
  await support.getByRole('button', { name: 'Confirmar y enviar este correo' }).click();
  await expect(support.getByRole('status')).toContainText('Aceptado por el servidor SMTP');
  await expect(
    support.getByRole('button', { name: 'Confirmar y enviar este correo' }),
  ).toBeDisabled();
  expect(supportSends).toBe(1);
  await page.getByLabel('Periodo de análisis').selectOption('168');
  const panel = page.getByRole('region', { name: 'Estado de los indicadores del servidor' });
  await expect(panel.getByRole('article')).toHaveCount(7);
  await expect(
    panel.getByRole('article', { name: 'Latencia / tiempo de respuesta' }),
  ).toContainText('150 ms');
  await expect(panel.getByRole('status')).toContainText('Recibiendo datos · 7/7');
  await expect(panel.getByText('example.test', { exact: true })).toBeVisible();
  await expect(panel.getByRole('img', { name: /Evolución de example.test/ })).toBeVisible();
  await expect(panel).not.toContainText('GoAccess');
  await expect(panel).not.toContainText('Datos parciales');
  await expect(panel.getByText('2,22 GB', { exact: true })).toBeVisible();
  const swap = panel.getByRole('article', { name: 'Swap', exact: true });
  await expect(swap).toContainText('Uso sin determinar');
  await expect(swap.locator('.incident-segment.critical')).toHaveCount(0);
  await panel
    .getByRole('article', { name: 'CPU', exact: true })
    .locator('.incident-segment')
    .first()
    .hover();
  await expect(page.getByRole('tooltip')).toContainText('Sin incidencias registradas');
  await panel
    .getByRole('article', { name: 'Memoria RAM', exact: true })
    .locator('.incident-segment')
    .first()
    .focus();
  await expect(page.getByRole('tooltip')).toContainText('Aviso');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('operational-desktop.png'), fullPage: true });
  await panel.getByLabel('Ver detalle de conexiones por ip', { exact: true }).click();
  await expect(panel.getByText('3 conexiones · Proveedor de prueba')).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await swap.locator('.incident-segment').first().click();
  await expect(page.getByRole('tooltip')).toContainText('Sin muestras');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('operational-mobile.png'), fullPage: true });
  await page.getByRole('button', { name: 'Ataques y actividad IP', exact: true }).click();
  const threats = page.getByRole('region', { name: 'Ataques y actividad IP' });
  await expect(threats.getByText('192.0.2.1', { exact: true })).toBeVisible();
  await page.getByLabel('Ventana', { exact: true }).selectOption('60');
  await page.getByLabel('Agrupar por', { exact: true }).selectOption('networks');
  await expect(threats.getByText('192.0.2.0/24', { exact: true })).toBeVisible();
  await expect(threats.getByRole('button', { name: 'Copiar rango' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('ip-activity-mobile.png'), fullPage: true });
  expect(errors).toEqual([]);
});
