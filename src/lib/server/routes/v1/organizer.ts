import express, { Router } from 'express';
import organizerController from '../../controller/v1/organizer';

const router: Router = express.Router();

router.post('/organizer', organizerController);

export default router;
