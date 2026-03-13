import * as fs from 'fs';
import * as path from 'path';

export type ScriptTypeMap = Record<string, string[]>;

export function getScriptType(filename: string): string {
  const ext = path.extname(filename);
  return ext ? ext.slice(1) : 'no_extension';
}

export function organizeByScriptType(dir: string): ScriptTypeMap {
  const resolvedDir = path.resolve(dir);
  if (!fs.existsSync(resolvedDir) || !fs.statSync(resolvedDir).isDirectory()) {
    throw new Error(`Not a valid directory: ${dir}`);
  }

  const entries = fs.readdirSync(resolvedDir, { withFileTypes: true });
  const files = entries.filter((e) => e.isFile()).map((e) => e.name);

  const organized: ScriptTypeMap = files.reduce((acc: ScriptTypeMap, filename: string) => {
    const type = getScriptType(filename);
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(filename);
    return acc;
  }, {});

  for (const type of Object.keys(organized)) {
    const typeDir = path.join(resolvedDir, type);
    if (!fs.existsSync(typeDir)) {
      fs.mkdirSync(typeDir, { recursive: true });
    }
  }

  return organized;
}
