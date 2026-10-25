/** Reads a CSV of credentials: a header row, then one row per credential. */
export const COLUMNS = ['student_id', 'student_name', 'program', 'graduation_date', 'gpa', 'honors'] as const;
const REQUIRED = ['student_id', 'student_name', 'program', 'graduation_date'];
export const MAX_ROWS = 500;

export type CsvRow = Record<(typeof COLUMNS)[number], string>;

/** Splits CSV text into records, honouring quotes ("" is a quote inside a quoted field) and CRLF. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  const t = text.replace(/^﻿/, '');
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (quoted) {
      if (c === '"') {
        if (t[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && t[i + 1] === '\n') i++;
      row.push(field); field = '';
      rows.push(row); row = [];
    } else field += c;
  }
  if (quoted) throw new Error('A quoted value is never closed.');
  if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((v) => v.trim() !== ''));
}

/** Turns CSV text into credential rows, or throws an error naming the line at fault. */
export function readCredentials(text: string): CsvRow[] {
  const [head, ...body] = parseCsv(text);
  if (!head) throw new Error('The file is empty.');
  const names = head.map((h) => h.trim().toLowerCase());
  const missing = REQUIRED.filter((c) => !names.includes(c));
  if (missing.length) throw new Error(`The header row is missing: ${missing.join(', ')}.`);
  const unknown = names.filter((n) => !(COLUMNS as readonly string[]).includes(n));
  if (unknown.length) throw new Error(`Unknown column: ${unknown.join(', ')}.`);
  if (body.length === 0) throw new Error('There are no credential rows under the header.');
  if (body.length > MAX_ROWS) throw new Error(`At most ${MAX_ROWS} credentials per import (this file has ${body.length}).`);
  return body.map((cells, i) => {
    if (cells.length > names.length) throw new Error(`Line ${i + 2} has more values than the header has columns.`);
    const r = Object.fromEntries(COLUMNS.map((c) => [c, ''])) as CsvRow;
    names.forEach((n, j) => { r[n as keyof CsvRow] = (cells[j] ?? '').trim(); });
    return r;
  });
}
