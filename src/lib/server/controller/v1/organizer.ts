import { Request, Response } from 'express';
import { organizeDirectory } from '../../../organizer';

const missingPathError = {
  success: false,
  reason: 'Missing required "path" body parameter',
};

export default function organizerController(req: Request, res: Response) {
  const dirPath = req.body?.path;
  if (!dirPath) return res.status(400).json(missingPathError);

  try {
    const result = organizeDirectory(String(dirPath));
    return res.status(200).json({ success: true, result });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return res.status(400).json({ success: false, reason: message });
  }
}
