import { Request, Response } from 'express';
import { organizeByScriptType } from '../../../organizer';

export default async function organizerController(req: Request, res: Response) {
  const { dir } = req.body;

  if (!dir) {
    res.status(422).json({
      success: false,
      reason: 'Missing required parameter: dir',
    });
    return;
  }

  try {
    const result = organizeByScriptType(dir);
    res.status(200).json({
      success: true,
      result,
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      reason: (e as Error).message,
    });
  }
}
