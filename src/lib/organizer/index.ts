import * as fs from 'fs';
import * as path from 'path';

export type FileCategory =
  | 'images'
  | 'videos'
  | 'audio'
  | 'documents'
  | 'scripts'
  | 'styles'
  | 'data'
  | 'archives'
  | 'others';

export type OrganizeResult = {
  category: FileCategory;
  files: string[];
};

export type OrganizerResponse = {
  organized: OrganizeResult[];
  skipped: string[];
};

export const FILE_TYPE_MAP: Record<string, FileCategory> = {
  // Images
  jpg: 'images',
  jpeg: 'images',
  png: 'images',
  gif: 'images',
  svg: 'images',
  webp: 'images',
  ico: 'images',
  bmp: 'images',
  tiff: 'images',
  tif: 'images',
  // Videos
  mp4: 'videos',
  avi: 'videos',
  mov: 'videos',
  mkv: 'videos',
  webm: 'videos',
  flv: 'videos',
  wmv: 'videos',
  // Audio
  mp3: 'audio',
  wav: 'audio',
  ogg: 'audio',
  flac: 'audio',
  aac: 'audio',
  m4a: 'audio',
  // Documents
  pdf: 'documents',
  doc: 'documents',
  docx: 'documents',
  xls: 'documents',
  xlsx: 'documents',
  ppt: 'documents',
  pptx: 'documents',
  txt: 'documents',
  md: 'documents',
  csv: 'documents',
  rtf: 'documents',
  // Scripts
  js: 'scripts',
  ts: 'scripts',
  py: 'scripts',
  sh: 'scripts',
  bash: 'scripts',
  rb: 'scripts',
  php: 'scripts',
  go: 'scripts',
  rs: 'scripts',
  java: 'scripts',
  c: 'scripts',
  cpp: 'scripts',
  cs: 'scripts',
  swift: 'scripts',
  kt: 'scripts',
  // Styles
  css: 'styles',
  scss: 'styles',
  sass: 'styles',
  less: 'styles',
  // Data
  json: 'data',
  xml: 'data',
  yaml: 'data',
  yml: 'data',
  toml: 'data',
  ini: 'data',
  env: 'data',
  // Archives
  zip: 'archives',
  tar: 'archives',
  gz: 'archives',
  rar: 'archives',
  '7z': 'archives',
  bz2: 'archives',
};

export function getCategoryForFile(filename: string): FileCategory {
  const ext = path.extname(filename).replace('.', '').toLowerCase();
  return FILE_TYPE_MAP[ext] || 'others';
}

export function organizeDirectory(dirPath: string): OrganizerResponse {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`Directory does not exist: ${dirPath}`);
  }

  const stat = fs.statSync(dirPath);
  if (!stat.isDirectory()) {
    throw new Error(`Path is not a directory: ${dirPath}`);
  }

  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const categorized: Partial<Record<FileCategory, string[]>> = {};
  const skipped: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      skipped.push(entry.name);
      continue;
    }

    const category = getCategoryForFile(entry.name);
    if (!categorized[category]) {
      categorized[category] = [];
    }
    (categorized[category] as string[]).push(entry.name);
  }

  const organized: OrganizeResult[] = [];

  for (const [category, files] of Object.entries(categorized) as [FileCategory, string[]][]) {
    const categoryDir = path.join(dirPath, category);

    if (!fs.existsSync(categoryDir)) {
      fs.mkdirSync(categoryDir);
    }

    for (const file of files) {
      const src = path.join(dirPath, file);
      let dest = path.join(categoryDir, file);

      if (fs.existsSync(dest)) {
        const ext = path.extname(file);
        const base = path.basename(file, ext);
        let counter = 1;
        do {
          dest = path.join(categoryDir, `${base}_${counter}${ext}`);
          counter++;
        } while (fs.existsSync(dest));
      }

      fs.renameSync(src, dest);
    }

    organized.push({ category, files });
  }

  return { organized, skipped };
}
