export const resourceLabels: Record<string, string> = {
  ram_free: 'RAM física libre',
  swap_free: 'Swap libre',
  cpu: 'CPU',
  load: 'Carga del servidor',
  processes: 'Procesos',
  tcp_connections: 'Conexiones TCP',
  http_processes: 'Procesos HTTP',
};
export const numeric = (value: number | null | undefined) =>
  value == null
    ? 'Sin dato'
    : new Intl.NumberFormat('es', { maximumFractionDigits: 2 }).format(value);
export function memory(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  const index = Math.min(4, Math.max(0, Math.floor(Math.log10(Math.max(1, Math.abs(bytes))) / 3)));
  return `${numeric(bytes / 1000 ** index)} ${units[index]}`;
}
export const subjectText = (subject: string) =>
  subject.startsWith('resource:')
    ? resourceLabels[subject.slice(9)] || subject.slice(9)
    : `Dominio: ${subject.replace('domain:', '')}`;
export function incidentExplanation(
  subject: string,
  feature: string,
  value: number,
  median: number | undefined,
  factor?: number,
) {
  const fmt = (n: number | undefined) =>
    n == null ? 'sin referencia' : factor ? memory(n * factor) : numeric(n);
  if (subject.startsWith('domain:')) {
    const observed =
      feature === 'active' ? 'conexiones activas observadas' : 'apariciones en la tabla Apache';
    return `${fmt(value)} ${observed}; lo habitual era ${fmt(median)}. ${median === 0 ? 'El dominio suele estar inactivo en las muestras: no se puede calcular un multiplicador respecto a cero.' : median && median > 0 ? `Supone ${numeric(value / median)} veces su valor habitual.` : ''}`;
  }
  const change =
    median && median > 0
      ? `${numeric(Math.abs(value / median - 1) * 100)} % ${value < median ? 'menos' : 'más'} que su valor habitual`
      : 'sin porcentaje comparable';
  return `${subjectText(subject)}: ${fmt(value)} frente a ${fmt(median)} habituales (${change}).`;
}
