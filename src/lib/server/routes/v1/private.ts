import express, { Router } from 'express';
import privateController from '../../controller/v1/private';
import forensicAuditController from '../../controller/v1/forensicAudit';

const router: Router = express.Router();

router.get('/private', privateController);
router.post('/private/audit', forensicAuditController);

export default router;
