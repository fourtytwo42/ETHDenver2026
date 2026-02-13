import fs from 'node:fs';
import path from 'node:path';

import Ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020';

type ValidationResult<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      details: {
        errors: Array<{ path: string; message: string }>;
      };
    };

const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
const validators = new Map<string, ValidateFunction>();

function loadSchema(schemaFile: string): object {
  const cwd = process.cwd();
  const candidates = [
    path.join(cwd, 'packages', 'shared-schemas', 'json', schemaFile),
    path.join(cwd, '..', 'packages', 'shared-schemas', 'json', schemaFile),
    path.join(cwd, '..', '..', 'packages', 'shared-schemas', 'json', schemaFile)
  ];

  const schemaPath = candidates.find((candidate) => fs.existsSync(candidate));
  if (!schemaPath) {
    throw new Error(`Schema file not found: ${schemaFile}`);
  }

  const raw = fs.readFileSync(schemaPath, 'utf8');
  return JSON.parse(raw) as object;
}

function getValidator(schemaFile: string): ValidateFunction {
  const existing = validators.get(schemaFile);
  if (existing) {
    return existing;
  }

  const schema = loadSchema(schemaFile);
  const compiled = ajv.compile(schema);
  validators.set(schemaFile, compiled);
  return compiled;
}

function normalizeErrors(errors: ErrorObject[] | null | undefined): Array<{ path: string; message: string }> {
  if (!errors) {
    return [];
  }

  return errors.map((err) => ({
    path: err.instancePath || '/',
    message: err.message || 'invalid value'
  }));
}

export function validatePayload<T>(schemaFile: string, payload: unknown): ValidationResult<T> {
  const validator = getValidator(schemaFile);
  const isValid = validator(payload);
  if (!isValid) {
    return {
      ok: false,
      details: {
        errors: normalizeErrors(validator.errors)
      }
    };
  }

  return {
    ok: true,
    data: payload as T
  };
}
