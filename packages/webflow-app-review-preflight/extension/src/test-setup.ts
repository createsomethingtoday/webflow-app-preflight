import * as matchers from '@testing-library/jest-dom/matchers';
import { expect } from 'vitest';

// Extend the same Vitest instance that runs this workspace. In a standalone
// pnpm workspace, jest-dom's convenience entrypoint can resolve a different
// hoisted Vitest version when other tooling also depends on Vitest.
expect.extend(matchers);
