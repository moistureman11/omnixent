import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { organizeDirectory, getCategoryForFile, FILE_TYPE_MAP } from '../index';

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omnixent-organizer-'));
}

function createFile(dir: string, name: string) {
  fs.writeFileSync(path.join(dir, name), '');
}

describe('getCategoryForFile', () => {
  it('categorizes image extensions correctly', () => {
    expect(getCategoryForFile('photo.jpg')).toBe('images');
    expect(getCategoryForFile('icon.PNG')).toBe('images');
    expect(getCategoryForFile('logo.svg')).toBe('images');
  });

  it('categorizes video extensions correctly', () => {
    expect(getCategoryForFile('movie.mp4')).toBe('videos');
    expect(getCategoryForFile('clip.AVI')).toBe('videos');
  });

  it('categorizes audio extensions correctly', () => {
    expect(getCategoryForFile('song.mp3')).toBe('audio');
    expect(getCategoryForFile('track.flac')).toBe('audio');
  });

  it('categorizes document extensions correctly', () => {
    expect(getCategoryForFile('report.pdf')).toBe('documents');
    expect(getCategoryForFile('notes.txt')).toBe('documents');
    expect(getCategoryForFile('readme.md')).toBe('documents');
  });

  it('categorizes script extensions correctly', () => {
    expect(getCategoryForFile('app.js')).toBe('scripts');
    expect(getCategoryForFile('main.ts')).toBe('scripts');
    expect(getCategoryForFile('script.py')).toBe('scripts');
    expect(getCategoryForFile('run.sh')).toBe('scripts');
  });

  it('categorizes style extensions correctly', () => {
    expect(getCategoryForFile('style.css')).toBe('styles');
    expect(getCategoryForFile('theme.scss')).toBe('styles');
  });

  it('categorizes data extensions correctly', () => {
    expect(getCategoryForFile('config.json')).toBe('data');
    expect(getCategoryForFile('settings.yaml')).toBe('data');
    expect(getCategoryForFile('vars.env')).toBe('data');
  });

  it('categorizes archive extensions correctly', () => {
    expect(getCategoryForFile('backup.zip')).toBe('archives');
    expect(getCategoryForFile('tarball.tar')).toBe('archives');
  });

  it('falls back to others for unknown extensions', () => {
    expect(getCategoryForFile('unknown.xyz')).toBe('others');
    expect(getCategoryForFile('noextension')).toBe('others');
  });
});

describe('organizeDirectory', () => {
  it('throws when directory does not exist', () => {
    expect(() => organizeDirectory('/non/existent/path')).toThrow('Directory does not exist');
  });

  it('throws when path is a file, not a directory', () => {
    const tmpDir = createTempDir();
    const filePath = path.join(tmpDir, 'file.txt');
    fs.writeFileSync(filePath, '');
    expect(() => organizeDirectory(filePath)).toThrow('Path is not a directory');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('moves files into category subdirectories', () => {
    const tmpDir = createTempDir();
    createFile(tmpDir, 'photo.jpg');
    createFile(tmpDir, 'app.js');
    createFile(tmpDir, 'report.pdf');

    const result = organizeDirectory(tmpDir);

    expect(fs.existsSync(path.join(tmpDir, 'images', 'photo.jpg'))).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'scripts', 'app.js'))).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'documents', 'report.pdf'))).toBe(true);

    expect(result.organized.find((o) => o.category === 'images')?.files).toContain('photo.jpg');
    expect(result.organized.find((o) => o.category === 'scripts')?.files).toContain('app.js');
    expect(result.organized.find((o) => o.category === 'documents')?.files).toContain('report.pdf');

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('skips existing subdirectories', () => {
    const tmpDir = createTempDir();
    fs.mkdirSync(path.join(tmpDir, 'subdir'));
    createFile(tmpDir, 'photo.jpg');

    const result = organizeDirectory(tmpDir);

    expect(result.skipped).toContain('subdir');

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('returns an empty organized array for an empty directory', () => {
    const tmpDir = createTempDir();

    const result = organizeDirectory(tmpDir);

    expect(result.organized).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('handles filename collisions by appending a counter', () => {
    const tmpDir = createTempDir();
    // Pre-create the category directory with a file of the same name
    fs.mkdirSync(path.join(tmpDir, 'scripts'));
    fs.writeFileSync(path.join(tmpDir, 'scripts', 'app.js'), 'existing');
    createFile(tmpDir, 'app.js');

    organizeDirectory(tmpDir);

    // Original file in category dir should still exist
    expect(fs.existsSync(path.join(tmpDir, 'scripts', 'app.js'))).toBe(true);
    // New file should be renamed with _1 suffix
    expect(fs.existsSync(path.join(tmpDir, 'scripts', 'app_1.js'))).toBe(true);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('places files with unknown extensions into others', () => {
    const tmpDir = createTempDir();
    createFile(tmpDir, 'weird.xyz');

    const result = organizeDirectory(tmpDir);

    expect(fs.existsSync(path.join(tmpDir, 'others', 'weird.xyz'))).toBe(true);
    expect(result.organized.find((o) => o.category === 'others')?.files).toContain('weird.xyz');

    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('FILE_TYPE_MAP', () => {
  it('contains entries for common image formats', () => {
    expect(FILE_TYPE_MAP['jpg']).toBe('images');
    expect(FILE_TYPE_MAP['png']).toBe('images');
  });

  it('contains entries for common script formats', () => {
    expect(FILE_TYPE_MAP['js']).toBe('scripts');
    expect(FILE_TYPE_MAP['py']).toBe('scripts');
  });
});
