import express, { Router } from 'express';
import privateController from '../../controller/v1/private';
import forensicAuditController from '../../controller/v1/forensicAudit';
import createRateLimit from '../../middleware/rateLimit';

const router: Router = express.Router();
const privateRateLimit = createRateLimit(60, 60 * 1000);

router.get('/private', privateRateLimit, privateController);
router.post('/private/audit', privateRateLimit, forensicAuditController);

export default router;
