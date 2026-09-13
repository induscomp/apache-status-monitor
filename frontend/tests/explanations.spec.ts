import { expect, test } from '@playwright/test';
import { incidentExplanation, memory, subjectText } from '../src/incidentText';

test('incident presentation distinguishes zero baseline, byte scale and resource identity', () => {
  const text = incidentExplanation('domain:example.test', 'active', 10, 0);
  expect(text).toContain('10 conexiones activas observadas');
  expect(text).toContain('no se puede calcular un multiplicador respecto a cero');
  expect(text).not.toMatch(/Infinity|NaN|∞/);
  expect(memory(2220000000)).toBe('2,22 GB');
  expect(memory(66000000)).toBe('66 MB');
  expect(memory(0)).toBe('0 B');
  expect(subjectText('resource:ram_free')).toBe('RAM física libre');
  expect(incidentExplanation('resource:ram_free', 'ram_free', 20, 100, 1e9)).toContain(
    '80 % menos',
  );
});
