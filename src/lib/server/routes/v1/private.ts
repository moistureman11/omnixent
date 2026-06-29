import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';
import privateController from '../../controller/v1/private';
import forensicAuditController from '../../controller/v1/forensicAudit';

const router: Router = express.Router();
const privateRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    reason: 'Too many requests',
  },
});

router.get('/private', privateRateLimit, privateController);
router.post('/private/audit', privateRateLimit, forensicAuditController);

export default router;
