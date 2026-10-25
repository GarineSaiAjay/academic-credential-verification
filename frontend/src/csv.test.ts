import { describe, expect, it } from 'vitest';
import { MAX_ROWS, parseCsv, readCredentials } from './csv';

const HEAD = 'student_id,student_name,program,graduation_date,gpa,honors';

describe('parseCsv', () => {
  it('handles quotes, commas inside quotes, doubled quotes, CRLF and a BOM', () => {
    expect(parseCsv('﻿a,"b,c","d ""e"""\r\nf,g,h\r\n')).toEqual([['a', 'b,c', 'd "e"'], ['f', 'g', 'h']]);
  });
  it('allows a newline inside quotes and skips blank lines', () => {
    expect(parseCsv('a,"b\nc"\n\n \nd,e')).toEqual([['a', 'b\nc'], ['d', 'e']]);
  });
  it('rejects a quote that never closes', () => {
    expect(() => parseCsv('a,"b')).toThrow(/never closed/);
  });
});

describe('readCredentials', () => {
  it('maps columns by header name, in any order, optional columns blank', () => {
    const rows = readCredentials('program,student_id,graduation_date,student_name\nBSc,S1,2025-05-15, Ada \n');
    expect(rows).toEqual([{ student_id: 'S1', student_name: 'Ada', program: 'BSc', graduation_date: '2025-05-15', gpa: '', honors: '' }]);
  });
  it('keeps optional values', () => {
    expect(readCredentials(`${HEAD}\nS1,Ada,BSc,2025-05-15,3.9,First class`)[0]).toMatchObject({ gpa: '3.9', honors: 'First class' });
  });
  it('names what is wrong', () => {
    expect(() => readCredentials('')).toThrow(/empty/);
    expect(() => readCredentials('student_id,program\nS1,BSc')).toThrow(/missing: student_name, graduation_date/);
    expect(() => readCredentials(`${HEAD},ssn\nS1,A,B,2025-05-15,,,1`)).toThrow(/Unknown column: ssn/);
    expect(() => readCredentials(`${HEAD}\n`)).toThrow(/no credential rows/);
    expect(() => readCredentials(`${HEAD}\nS1,A,B,2025-05-15,,,x,y`)).toThrow(/Line 2/);
  });
  it('refuses more rows than the server accepts', () => {
    const body = Array.from({ length: MAX_ROWS + 1 }, (_, i) => `S${i},A,B,2025-05-15,,`).join('\n');
    expect(() => readCredentials(`${HEAD}\n${body}`)).toThrow(/At most 500/);
  });
});
