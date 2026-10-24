import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
import { setSession } from './api';

afterEach(() => {
  cleanup();
  setSession(null);
  sessionStorage.clear();
  window.location.hash = '';
});
