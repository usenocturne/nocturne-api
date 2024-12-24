import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import https from 'https';
import fs from 'fs';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());

const deviceSessions = new Map();

app.use(express.static('public'));
app.use(express.json());
app.set('views', path.join(__dirname, '../views'));
app.set('view engine', 'html');
app.engine('html', (await import('ejs')).default.renderFile);

app.get('/', (req, res) => {
    res.send("Hello World!");
});

app.post('/v1/auth/register-device', (req, res) => {
    const deviceId = crypto.randomBytes(16).toString('hex');
    const salt = crypto.randomBytes(8).toString('hex');
    const encryptionKey = crypto.createHash('sha256').update(deviceId).digest('hex').slice(0, 32);

    deviceSessions.set(deviceId, {
        status: 'pending',
        encryptionKey,
        salt
    });

    setTimeout(() => {
        deviceSessions.delete(deviceId);
    }, 600000);

    res.json({ deviceId, salt });
});

app.post('/v1/auth/store-secret/:deviceId', (req, res) => {
    const { encryptedData } = req.body;

    const session = deviceSessions.get(req.params.deviceId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }

    deviceSessions.set(req.params.deviceId, {
        ...session,
        encryptedData
    });

    res.json({ success: true });
});

app.get('/v1/auth/check-status/:deviceId', (req, res) => {
    const session = deviceSessions.get(req.params.deviceId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }

    res.json(session);
});

app.get("/v1/auth/ui/:deviceId", (req, res) => {
    const session = deviceSessions.get(req.params.deviceId);
    if (!session) {
        return res.status(404).json({ error: 'Invalid or expired session' });
    }

    res.render('auth.html', {
        deviceId: req.params.deviceId,
        salt: session.salt,
        baseUrl: process.env.BASE_URL || `http://localhost:${port}`
    });
});

app.get('/v1/auth/callback', (req, res) => {
    const { code, state } = req.query;

    const session = deviceSessions.get(state);
    if (!session) {
        return res.status(404).json({ error: 'Session expired' });
    }

    deviceSessions.set(state, {
        ...session,
        status: 'authorized',
        code
    });

    res.render('auth-result.html');
});

const httpsOptions = {
    key: fs.readFileSync('cert.key'),
    cert: fs.readFileSync('cert.crt')
};

const server = https.createServer(httpsOptions, app);
server.listen(port, "0.0.0.0", () => {
    console.log(`Server is running at https://localhost:${port}`);
});

export default app;
