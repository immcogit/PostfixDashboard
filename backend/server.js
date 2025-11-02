// ============================================
// FIXED: backend/server.js
// ============================================
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const zlib = require('zlib');
const { promisify } = require('util');
const { GoogleGenAI, Type } = require('@google/genai');
const crypto = require('crypto');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Define allowed origins based on environment (local IP or Nginx Proxy URL)
const allowedOrigins = [
  'http://192.168.5.2',  // Your local frontend IP
  'http://localhost',    // For local development
  'https://productionurl.example.in',  // Nginx URL (change this to your production URL)
];

// Configure CORS to allow specific origins
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests from allowed origins or if there's no origin (e.g., mobile apps)
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],  // You can customize this based on your app
};

// Apply CORS middleware with options
app.use(cors(corsOptions));
app.use(express.json());

// --- CONFIGURATION ---
const config = {
  server: {
    port: PORT,
    logLevel: process.env.LOG_LEVEL || 'info',
    enableRequestLogging: process.env.ENABLE_REQUEST_LOGGING === 'true',
  },
  postfix: {
    logPath: process.env.POSTFIX_LOG_PATH || '/var/log/mail.log',
    configPath: process.env.POSTFIX_CONFIG_PATH || '/etc/postfix/main.cf',
    logDir: path.dirname(process.env.POSTFIX_LOG_PATH || '/var/log/mail.log'),
    logPrefix: path.basename(process.env.POSTFIX_LOG_PATH || '/var/log/mail.log'),
  },
  auth: {
    tokenSecret: process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex'),
    tokenExpiryHours: parseInt(process.env.TOKEN_EXPIRY_HOURS || '24'),
    dashboardUser: process.env.DASHBOARD_USER,
    dashboardPassword: process.env.DASHBOARD_PASSWORD,
  },
  ai: {
    provider: process.env.AI_PROVIDER || 'ollama',
    gemini: {
      apiKey: process.env.GEMINI_API_KEY || process.env.API_KEY,
      model: process.env.GEMINI_MODEL || 'gemini-2.0-flash-exp',
    },
    ollama: {
      baseUrl: process.env.OLLAMA_API_BASE_URL || 'http://localhost:11434',
      model: process.env.OLLAMA_MODEL || 'llama3.2:latest',
    },
    analysis: {
      maxLogs: parseInt(process.env.AI_ANALYSIS_MAX_LOGS || '200'),
      defaultLogs: parseInt(process.env.AI_ANALYSIS_DEFAULT_LOGS || '50'),
      timeout: parseInt(process.env.AI_ANALYSIS_TIMEOUT || '60000'),
    },
  },
};

// Logging utility
const logger = {
  info: (...args) => console.log('[INFO]', new Date().toISOString(), ...args),
  error: (...args) => console.error('[ERROR]', new Date().toISOString(), ...args),
  warn: (...args) => console.warn('[WARN]', new Date().toISOString(), ...args),
  debug: (...args) => config.server.logLevel === 'debug' && console.log('[DEBUG]', new Date().toISOString(), ...args),
};

// Request logging middleware
if (config.server.enableRequestLogging) {
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
    });
    next();
  });
}

// Gemini AI Setup
let ai;
if (config.ai.gemini.apiKey && config.ai.gemini.apiKey !== 'YOUR_GEMINI_API_KEY_HERE') {
  ai = new GoogleGenAI({ apiKey: config.ai.gemini.apiKey });
  logger.info('Gemini AI initialized successfully');
}

// --- CACHING ---
let logCache = {
  logs: [],
  stats: {},
  volume: [],
  lastModified: 0,
};

// Promisify zlib.gunzip for async/await
const gunzip = promisify(zlib.gunzip);

// --- AUTH UTILITIES ---

function generateToken(email) {
  const payload = {
    email,
    iat: Date.now(),
    exp: Date.now() + (config.auth.tokenExpiryHours * 60 * 60 * 1000),
  };
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  return token;
}

function verifyToken(token) {
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    if (Date.now() > payload.exp) {
      return null;
    }
    return payload;
  } catch (error) {
    logger.error('Token verification failed:', error.message);
    return null;
  }
}

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'No authorization header provided.' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
  const payload = verifyToken(token);
  
  if (!payload) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }

  req.user = payload;
  next();
}

// --- LOG PARSING ENGINE ---

const parseDate = (dateString) => {
    let date = new Date(dateString);
    if (!isNaN(date.getTime())) {
        return date;
    }

    const monthMap = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const parts = dateString.match(/(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})/);
    if (parts) {
        const now = new Date();
        let year = now.getFullYear();
        const month = monthMap[parts[1]];
        const day = parseInt(parts[2], 10);
        
        if (month > now.getMonth()) {
            year--;
        }

        return new Date(year, month, day, parseInt(parts[3], 10), parseInt(parts[4], 10), parseInt(parts[5], 10));
    }
    
    return null;
};

const parseLogLine = (line) => {
    const dateMatch = line.match(/^(?:(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})|([0-9T:.\-+]+))\s+/);
    if (!dateMatch) return null;

    const rawTimestamp = dateMatch[1] || dateMatch[2];
    const timestamp = parseDate(rawTimestamp);
    if (!timestamp) return null;

    const content = line.substring(dateMatch[0].length);
    const parts = content.match(/(\S+)\s+postfix\/(\w+)\[(\d+)\]:\s+(.*)/);
    if (!parts) return null;

    const [, hostname, process, pid, message] = parts;
    const queueIdMatch = message.match(/^([A-F0-9]{10,})/);
    const queueId = queueIdMatch ? queueIdMatch[1] : null;

    return {
        timestamp,
        hostname,
        process,
        message,
        queueId,
        line
    };
};

const aggregateLogs = (parsedLogs) => {
    const messages = {};

    for (const log of parsedLogs) {
        if (!log || !log.queueId) continue;

        if (!messages[log.queueId]) {
            messages[log.queueId] = {
                id: log.queueId,
                timestamp: log.timestamp,
                from: null,
                to: null,
                status: 'info',
                detail: '',
                lines: [],
            };
        }

        const msg = messages[log.queueId];
        msg.lines.push(log.line);

        const fromMatch = log.message.match(/from=<([^>]+)>/);
        if (fromMatch) msg.from = fromMatch[1] || 'N/A';

        const toMatch = log.message.match(/to=<([^>]+)>/);
        if (toMatch) msg.to = toMatch[1] || 'N/A';

        const statusMatch = log.message.match(/status=(\w+)/);
        if (statusMatch) {
            msg.status = statusMatch[1].toLowerCase();
            msg.detail = log.message;
            msg.timestamp = log.timestamp;
        }
    }

    return Object.values(messages)
        .filter(m => m.from || m.to)
        .map(m => ({
            ...m,
            from: m.from || 'N/A',
            to: m.to || 'N/A',
            detail: m.detail || m.lines[m.lines.length - 1] || 'No details available.'
        }))
        .sort((a, b) => b.timestamp - a.timestamp);
};

const readAndParseLogs = async () => {
  logger.info('Reading and parsing all log files...');
  let allLines = [];
  try {
    const files = await fs.readdir(config.postfix.logDir);
    const logFiles = files.filter(f => f.startsWith(config.postfix.logPrefix)).sort().reverse();

    for (const file of logFiles) {
      const filePath = path.join(config.postfix.logDir, file);
      let content;
      if (file.endsWith('.gz')) {
        const compressedData = await fs.readFile(filePath);
        content = (await gunzip(compressedData)).toString('utf8');
      } else {
        content = await fs.readFile(filePath, 'utf8');
      }
      allLines.push(...content.split('\n'));
    }

    const parsedLogs = allLines.map(parseLogLine).filter(Boolean);
    logger.info(`Successfully parsed ${parsedLogs.length} log entries`);
    return aggregateLogs(parsedLogs);
  } catch (error) {
    logger.error(`Error reading log files: ${error.message}`);
    return [];
  }
};

const getLogs = async () => {
  try {
    const stats = await fs.stat(config.postfix.logPath);
    if (stats.mtimeMs > logCache.lastModified) {
      logger.info('Log file changed, re-parsing...');
      const aggregatedLogs = await readAndParseLogs();
      
      logCache.logs = aggregatedLogs;
      logCache.lastModified = stats.mtimeMs;
    } else {
       logger.debug('Serving logs from cache.');
    }
  } catch (error) {
    if (error.code === 'ENOENT' && logCache.logs.length === 0) {
       logger.warn('Main log not found, trying to parse rotated logs...');
       logCache.logs = await readAndParseLogs();
       logCache.lastModified = Date.now();
    } else if (error.code !== 'ENOENT') {
       logger.error(`Error checking log file status: ${error.message}`);
    }
  }
  return logCache.logs;
};

// --- API ENDPOINTS ---

const validateInputs = (req, res, next) => {
    if (req.path === '/api/login') {
        const { email, password } = req.body;
        if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ message: 'Email and password are required.' });
        }
    }
    next();
};

app.post('/api/login', validateInputs, (req, res) => {
    const { email, password } = req.body;

    if (email === config.auth.dashboardUser && password === config.auth.dashboardPassword) {
        const token = generateToken(email);
        logger.info(`User logged in: ${email}`);
        res.status(200).json({ 
            message: 'Login successful',
            token: token,
        });
    } else {
        logger.warn(`Failed login attempt for: ${email}`);
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.get('/api/logs', authenticate, async (req, res) => {
    try {
        let logs = await getLogs();
        const { startDate, endDate, limit, page, status } = req.query;

        if (startDate) {
            logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
        }
        if (endDate) {
            const endOfDay = new Date(endDate);
            endOfDay.setHours(23, 59, 59, 999);
            logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
        }

        if (status && status !== 'all') {
            logs = logs.filter(log => log.status === status);
        }

        const totalItems = logs.length;

        if (page && limit) {
            const pageNum = parseInt(page, 10);
            const pageSize = parseInt(limit, 10);
            if (!isNaN(pageNum) && !isNaN(pageSize) && pageNum > 0 && pageSize > 0) {
                const startIndex = (pageNum - 1) * pageSize;
                logs = logs.slice(startIndex, startIndex + pageSize);
            }
        } else if (limit) {
            const numLimit = parseInt(limit, 10);
            if (!isNaN(numLimit) && numLimit > 0) {
               logs = logs.slice(0, numLimit);
            }
        }

        res.json(logs);
    } catch (error) {
        logger.error('Error in /api/logs:', error);
        res.status(500).json({ error: 'Failed to retrieve logs.' });
    }
});

app.get('/api/stats', authenticate, async (req, res) => {
    try {
        let logs = await getLogs();
        const { startDate, endDate } = req.query;

        if (startDate) {
            logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
        }
        if (endDate) {
            const endOfDay = new Date(endDate);
            endOfDay.setHours(23, 59, 59, 999);
            logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
        }

        const stats = {
            total: logs.length,
            sent: logs.filter(l => l.status === 'sent').length,
            bounced: logs.filter(l => l.status === 'bounced').length,
            deferred: logs.filter(l => l.status === 'deferred').length,
            rejected: logs.filter(l => l.status === 'rejected').length,
        };
        res.json(stats);
    } catch (error) {
        logger.error('Error in /api/stats:', error);
        res.status(500).json({ error: 'Failed to calculate stats.' });
    }
});

app.get('/api/volume-trends', authenticate, async (req, res) => {
    try {
        let logs = await getLogs();
        const { startDate, endDate } = req.query;

        if (startDate) {
            logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
        }
        if (endDate) {
            const endOfDay = new Date(endDate);
            endOfDay.setHours(23, 59, 59, 999);
            logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
        }

        const volumeByDay = {};
        logs.forEach(log => {
            const date = new Date(log.timestamp).toISOString().split('T')[0];
            if (!volumeByDay[date]) {
                volumeByDay[date] = { date, sent: 0, bounced: 0, deferred: 0 };
            }
            if (log.status === 'sent') volumeByDay[date].sent++;
            if (log.status === 'bounced') volumeByDay[date].bounced++;
            if (log.status === 'deferred') volumeByDay[date].deferred++;
        });

        const sortedVolume = Object.values(volumeByDay).sort((a,b) => new Date(a.date) - new Date(b.date));

        res.json(sortedVolume);
    } catch (error) {
        logger.error('Error in /api/volume-trends:', error);
        res.status(500).json({ error: 'Failed to generate volume trends.' });
    }
});

app.get('/api/recent-activity', authenticate, async (req, res) => {
    try {
        const logs = await getLogs();
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentLogs = logs.filter(log => new Date(log.timestamp) > twentyFourHoursAgo);

        const activities = [];
        recentLogs.forEach((log, index) => {
            const line = log.detail.toLowerCase();
            if (line.includes('relay access denied')) {
                activities.push({ id: `sec-${index}`, timestamp: log.timestamp, type: 'security', description: `Relay access denied for a client.` });
            } else if (line.includes('terminating on signal')) {
                activities.push({ id: `sys-${index}`, timestamp: log.timestamp, type: 'system', description: 'Postfix service was stopped or terminated.' });
            } else if (line.includes('daemon started')) {
                activities.push({ id: `sys-${index}`, timestamp: log.timestamp, type: 'system', description: 'Postfix service started.' });
            }
        });
        res.json(activities.slice(0, 5));
    } catch (error) {
        logger.error('Error in /api/recent-activity:', error);
        res.status(500).json({ error: 'Failed to get recent activity.' });
    }
});

app.get('/api/allowed-networks', authenticate, async (req, res) => {
  try {
    const data = await fs.readFile(config.postfix.configPath, 'utf8');
    const lines = data.split('\n');
    const mynetworksLine = lines.find(line => line.trim().startsWith('mynetworks') && !line.trim().startsWith('#'));
    if (mynetworksLine) {
      const [, value] = mynetworksLine.split('=').map(s => s.trim());
      const networks = value.split(/[\s,]+/).filter(Boolean);
      res.json(networks);
    } else {
      res.json([]);
    }
  } catch (error) {
    logger.error(`Error reading Postfix config: ${error.message}`);
    res.status(500).json({ error: `Could not read Postfix config file at ${config.postfix.configPath}` });
  }
});

app.post('/api/allowed-networks', authenticate, async (req, res) => {
  try {
    const { networks } = req.body;
    
    if (!Array.isArray(networks)) {
      return res.status(400).json({ error: 'Networks must be an array' });
    }

    const validNetworks = networks.filter(net => {
      const trimmed = net.trim();
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
      const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?(\/\d{1,3})?$/;
      return trimmed && (ipRegex.test(trimmed) || hostnameRegex.test(trimmed) || ipv6Regex.test(trimmed));
    });

    if (validNetworks.length === 0) {
      return res.status(400).json({ error: 'No valid networks provided' });
    }

    const data = await fs.readFile(config.postfix.configPath, 'utf8');
    const lines = data.split('\n');
    
    let found = false;
    const newLines = lines.map(line => {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('mynetworks') && !trimmedLine.startsWith('#')) {
        found = true;
        return `mynetworks = ${validNetworks.join(' ')}`;
      }
      return line;
    });

    if (!found) {
      newLines.push(`mynetworks = ${validNetworks.join(' ')}`);
    }

    await fs.writeFile(config.postfix.configPath, newLines.join('\n'), 'utf8');

    logger.info(`Updated mynetworks: ${validNetworks.join(' ')}`);

    res.json({ 
      message: 'Networks updated successfully. Please reload Postfix configuration.',
      networks: validNetworks
    });
  } catch (error) {
    logger.error(`Error updating Postfix config: ${error.message}`);
    
    if (error.code === 'EACCES') {
      res.status(500).json({ 
        error: `Permission denied. The server cannot write to ${config.postfix.configPath}. Please check file permissions.` 
      });
    } else if (error.code === 'ENOENT') {
      res.status(500).json({ 
        error: `Config file not found at ${config.postfix.configPath}. Please check the POSTFIX_CONFIG_PATH in your .env file.` 
      });
    } else {
      res.status(500).json({ 
        error: `Could not update Postfix config file. ${error.message}` 
      });
    }
  }
});

// ============================================
// FIXED ANALYTICS ENDPOINTS WITH CORRECT LOCAL IP TRACKING
// ============================================

// *** CORRECTED IP EXTRACTION FUNCTIONS ***

// Helper to extract ANY IP from a log line (fallback)
const extractIPFromLog = (line) => {
  const ipMatch = line.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  if (ipMatch) return ipMatch[1];
  
  const ipv6Match = line.match(/\[([0-9a-fA-F:]+)\]/);
  if (ipv6Match) return ipv6Match[1];
  
  return null;
};

// *** FIXED: This now extracts LOCAL sender IPs (client/connect) NOT relay IPs ***
const extractRelayIP = (line) => {
  // PRIORITY 1: Look for "connect from" - this is the ORIGINAL sender
  const connectMatch = line.match(/connect from [^\[]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  if (connectMatch) return connectMatch[1];
  
  // PRIORITY 2: Look for "client=" - this is also the ORIGINAL sender
  const clientMatch = line.match(/client=[^\[]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  if (clientMatch) return clientMatch[1];
  
  // IPv6 versions (less common but included for completeness)
  const connect6Match = line.match(/connect from [^\[]*\[([0-9a-fA-F:]+)\]/);
  if (connect6Match) return connect6Match[1];
  
  const client6Match = line.match(/client=[^\[]*\[([0-9a-fA-F:]+)\]/);
  if (client6Match) return client6Match[1];
  
  // DO NOT extract "relay=" IPs - those are DESTINATION relays (like Outlook)
  return null;
};

// GET /api/analytics/top-senders
app.get('/api/analytics/top-senders', authenticate, async (req, res) => {
  try {
    let logs = await getLogs();
    const { startDate, endDate, limit = 50 } = req.query;

    if (startDate) {
      logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
    }
    if (endDate) {
      const endOfDay = new Date(endDate);
      endOfDay.setHours(23, 59, 59, 999);
      logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
    }

    const senderCounts = {};
    const senderDetails = {};

    logs.forEach(log => {
      if (log.from && log.from !== 'N/A') {
        const sender = log.from.toLowerCase();
        
        if (!senderCounts[sender]) {
          senderCounts[sender] = {
            total: 0,
            sent: 0,
            bounced: 0,
            deferred: 0,
            rejected: 0
          };
          senderDetails[sender] = {
            email: log.from,
            firstSeen: log.timestamp,
            lastSeen: log.timestamp,
            relayIPs: new Set()
          };
        }

        senderCounts[sender].total++;
        senderCounts[sender][log.status]++;
        
        // Extract LOCAL IP from all log lines for this queue ID
        log.lines.forEach(line => {
          const relayIP = extractRelayIP(line);
          if (relayIP) {
            senderDetails[sender].relayIPs.add(relayIP);
          }
        });
        
        if (new Date(log.timestamp) < new Date(senderDetails[sender].firstSeen)) {
          senderDetails[sender].firstSeen = log.timestamp;
        }
        if (new Date(log.timestamp) > new Date(senderDetails[sender].lastSeen)) {
          senderDetails[sender].lastSeen = log.timestamp;
        }
      }
    });

    const topSenders = Object.entries(senderCounts)
      .map(([email, counts]) => ({
        email: senderDetails[email].email,
        totalMessages: counts.total,
        sent: counts.sent,
        bounced: counts.bounced,
        deferred: counts.deferred,
        rejected: counts.rejected,
        successRate: counts.total > 0 ? ((counts.sent / counts.total) * 100).toFixed(1) : '0.0',
        firstSeen: senderDetails[email].firstSeen,
        lastSeen: senderDetails[email].lastSeen,
        relayIPs: Array.from(senderDetails[email].relayIPs)
      }))
      .sort((a, b) => b.totalMessages - a.totalMessages)
      .slice(0, parseInt(limit));

    res.json({
      total: Object.keys(senderCounts).length,
      data: topSenders
    });
  } catch (error) {
    logger.error('Error in /api/analytics/top-senders:', error);
    res.status(500).json({ error: 'Failed to retrieve top senders.' });
  }
});

// GET /api/analytics/top-recipients
app.get('/api/analytics/top-recipients', authenticate, async (req, res) => {
  try {
    let logs = await getLogs();
    const { startDate, endDate, limit = 50 } = req.query;

    if (startDate) {
      logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
    }
    if (endDate) {
      const endOfDay = new Date(endDate);
      endOfDay.setHours(23, 59, 59, 999);
      logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
    }

    const recipientCounts = {};
    const recipientDetails = {};

    logs.forEach(log => {
      if (log.to && log.to !== 'N/A') {
        const recipient = log.to.toLowerCase();
        
        if (!recipientCounts[recipient]) {
          recipientCounts[recipient] = {
            total: 0,
            sent: 0,
            bounced: 0,
            deferred: 0,
            rejected: 0
          };
          recipientDetails[recipient] = {
            email: log.to,
            firstSeen: log.timestamp,
            lastSeen: log.timestamp,
            relayIPs: new Set()
          };
        }

        recipientCounts[recipient].total++;
        recipientCounts[recipient][log.status]++;
        
        // Extract LOCAL IP from all log lines for this queue ID
        log.lines.forEach(line => {
          const relayIP = extractRelayIP(line);
          if (relayIP) {
            recipientDetails[recipient].relayIPs.add(relayIP);
          }
        });
        
        if (new Date(log.timestamp) < new Date(recipientDetails[recipient].firstSeen)) {
          recipientDetails[recipient].firstSeen = log.timestamp;
        }
        if (new Date(log.timestamp) > new Date(recipientDetails[recipient].lastSeen)) {
          recipientDetails[recipient].lastSeen = log.timestamp;
        }
      }
    });

    const topRecipients = Object.entries(recipientCounts)
      .map(([email, counts]) => ({
        email: recipientDetails[email].email,
        totalMessages: counts.total,
        sent: counts.sent,
        bounced: counts.bounced,
        deferred: counts.deferred,
        rejected: counts.rejected,
        deliveryRate: counts.total > 0 ? ((counts.sent / counts.total) * 100).toFixed(1) : '0.0',
        firstSeen: recipientDetails[email].firstSeen,
        lastSeen: recipientDetails[email].lastSeen,
        relayIPs: Array.from(recipientDetails[email].relayIPs)
      }))
      .sort((a, b) => b.totalMessages - a.totalMessages)
      .slice(0, parseInt(limit));

    res.json({
      total: Object.keys(recipientCounts).length,
      data: topRecipients
    });
  } catch (error) {
    logger.error('Error in /api/analytics/top-recipients:', error);
    res.status(500).json({ error: 'Failed to retrieve top recipients.' });
  }
});

// GET /api/analytics/connected-ips
app.get('/api/analytics/connected-ips', authenticate, async (req, res) => {
  try {
    let logs = await getLogs();
    const { startDate, endDate, limit = 50 } = req.query;

    if (startDate) {
      logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
    }
    if (endDate) {
      const endOfDay = new Date(endDate);
      endOfDay.setHours(23, 59, 59, 999);
      logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
    }

    const ipCounts = {};
    const ipDetails = {};

    logs.forEach(log => {
      // Extract LOCAL IP from all log lines
      log.lines.forEach(line => {
        const ip = extractRelayIP(line); // Use the FIXED function
        
        if (ip) {
          if (!ipCounts[ip]) {
            ipCounts[ip] = {
              connections: 0,
              messages: 0,
              sent: 0,
              bounced: 0,
              deferred: 0,
              rejected: 0
            };
            ipDetails[ip] = {
              firstSeen: log.timestamp,
              lastSeen: log.timestamp,
              hostnames: new Set()
            };
          }

          ipCounts[ip].connections++;
          
          // Extract hostname if present
          const hostnameMatch = line.match(/(?:connect from|client=)\s+([^\[]+)\[/);
          if (hostnameMatch && hostnameMatch[1]) {
            const hostname = hostnameMatch[1].trim();
            if (hostname !== 'unknown') {
              ipDetails[ip].hostnames.add(hostname);
            }
          }
        }
      });
      
      // Count messages per IP (use the first IP found for this message)
      const firstIP = extractRelayIP(log.lines[0] || '');
      if (firstIP && ipCounts[firstIP]) {
        ipCounts[firstIP].messages++;
        ipCounts[firstIP][log.status]++;
        
        if (new Date(log.timestamp) < new Date(ipDetails[firstIP].firstSeen)) {
          ipDetails[firstIP].firstSeen = log.timestamp;
        }
        if (new Date(log.timestamp) > new Date(ipDetails[firstIP].lastSeen)) {
          ipDetails[firstIP].lastSeen = log.timestamp;
        }
      }
    });

    const topIPs = Object.entries(ipCounts)
      .map(([ip, counts]) => ({
        ip,
        connections: counts.connections,
        totalMessages: counts.messages,
        sent: counts.sent,
        bounced: counts.bounced,
        deferred: counts.deferred,
        rejected: counts.rejected,
        successRate: counts.messages > 0 ? ((counts.sent / counts.messages) * 100).toFixed(1) : '0.0',
        hostnames: Array.from(ipDetails[ip].hostnames),
        firstSeen: ipDetails[ip].firstSeen,
        lastSeen: ipDetails[ip].lastSeen
      }))
      .sort((a, b) => b.connections - a.connections)
      .slice(0, parseInt(limit));

    res.json({
      total: Object.keys(ipCounts).length,
      data: topIPs
    });
  } catch (error) {
    logger.error('Error in /api/analytics/connected-ips:', error);
    res.status(500).json({ error: 'Failed to retrieve connected IPs.' });
  }
});

// GET /api/analytics/summary
app.get('/api/analytics/summary', authenticate, async (req, res) => {
  try {
    let logs = await getLogs();
    const { startDate, endDate } = req.query;

    if (startDate) {
      logs = logs.filter(log => new Date(log.timestamp) >= new Date(startDate));
    }
    if (endDate) {
      const endOfDay = new Date(endDate);
      endOfDay.setHours(23, 59, 59, 999);
      logs = logs.filter(log => new Date(log.timestamp) <= endOfDay);
    }

    const uniqueSenders = new Set();
    const uniqueRecipients = new Set();
    const uniqueIPs = new Set();
    const domains = { senders: new Set(), recipients: new Set() };

    logs.forEach(log => {
      if (log.from && log.from !== 'N/A') {
        uniqueSenders.add(log.from.toLowerCase());
        const domain = log.from.split('@')[1];
        if (domain) domains.senders.add(domain.toLowerCase());
      }
      
      if (log.to && log.to !== 'N/A') {
        uniqueRecipients.add(log.to.toLowerCase());
        const domain = log.to.split('@')[1];
        if (domain) domains.recipients.add(domain.toLowerCase());
      }

      // Extract LOCAL IPs
      log.lines.forEach(line => {
        const ip = extractRelayIP(line);
        if (ip) uniqueIPs.add(ip);
      });
    });

    res.json({
      uniqueSenders: uniqueSenders.size,
      uniqueRecipients: uniqueRecipients.size,
      uniqueIPs: uniqueIPs.size,
      senderDomains: domains.senders.size,
      recipientDomains: domains.recipients.size,
      totalMessages: logs.length,
      dateRange: {
        start: startDate || 'all',
        end: endDate || 'all'
      }
    });
  } catch (error) {
    logger.error('Error in /api/analytics/summary:', error);
    res.status(500).json({ error: 'Failed to retrieve analytics summary.' });
  }
});

logger.info('Analytics endpoints initialized successfully');

// ============================================
// AI LOG ANALYSIS
// ============================================

app.post('/api/analyze-logs', authenticate, async (req, res) => {
    const { logs, provider, ollamaUrl } = req.body;

    if (!logs || typeof logs !== 'string') {
        return res.status(400).json({ error: 'Log data is required.' });
    }

    const aiProvider = provider || config.ai.provider;

    if (aiProvider === 'gemini') {
        if (!ai) {
             return res.status(400).json({ error: 'Gemini API key is not configured on the server. Please set GEMINI_API_KEY in the .env file.' });
        }
        try {
            const prompt = `You are an expert Postfix mail server administrator and security analyst with deep knowledge of email infrastructure, SMTP protocols, and mail server security.

Analyze the following Postfix mail server logs in detail:

${logs}

Provide a comprehensive analysis in JSON format with the following structure:

{
  "summary": "A detailed 3-5 paragraph executive summary covering: overall mail server health, mail flow patterns, delivery success rates, any concerning trends, and recommendations for improvement.",
  
  "anomalies": [
    "List specific unusual patterns such as: sudden spikes in mail volume, unusual sender/recipient patterns, atypical delivery times, connection patterns from unexpected sources, deviations from normal behavior, rate limiting triggers, etc. Be specific with examples from the logs."
  ],
  
  "threats": [
    "List potential security threats including: relay access attempts, authentication failures, spam patterns, suspicious sender domains, potential brute force attacks, open relay attempts, malformed message patterns, connections from blacklisted IPs, etc. Include specific log entries as evidence."
  ],
  
  "errors": [
    "List configuration and operational errors such as: DNS lookup failures, connection timeouts, TLS/SSL certificate issues, queue management problems, disk space warnings, delivery failures, bounce patterns, temporary vs permanent failures, specific SMTP error codes encountered, etc."
  ],
  
  "statistics": {
    "totalMessages": "number of messages processed",
    "successRate": "percentage of successfully delivered messages",
    "bounceRate": "percentage of bounced messages",
    "deferredRate": "percentage of deferred messages",
    "topSenderDomains": ["list of most active sender domains"],
    "topRecipientDomains": ["list of most active recipient domains"],
    "peakActivityTime": "time period with highest activity"
  },
  
  "recommendations": [
    "Provide actionable recommendations such as: configuration changes needed, security improvements, performance optimizations, monitoring enhancements, policy adjustments, SPF/DKIM/DMARC improvements, queue management strategies, etc."
  ]
}

Focus on:
- Be specific and cite actual log entries when discussing issues
- Identify patterns across multiple log entries
- Distinguish between temporary issues and systemic problems
- Consider security implications of observed patterns
- Provide context for technical terms
- Prioritize findings by severity and impact`;

            const response = await ai.models.generateContent({
                model: config.ai.gemini.model,
                contents: prompt,
                config: {
                    responseMimeType: "application/json",
                    responseSchema: {
                        type: Type.OBJECT,
                        properties: {
                            summary: { type: Type.STRING },
                            anomalies: { type: Type.ARRAY, items: { type: Type.STRING } },
                            threats: { type: Type.ARRAY, items: { type: Type.STRING } },
                            errors: { type: Type.ARRAY, items: { type: Type.STRING } },
                            statistics: {
                                type: Type.OBJECT,
                                properties: {
                                    totalMessages: { type: Type.STRING },
                                    successRate: { type: Type.STRING },
                                    bounceRate: { type: Type.STRING },
                                    deferredRate: { type: Type.STRING },
                                    topSenderDomains: { type: Type.ARRAY, items: { type: Type.STRING } },
                                    topRecipientDomains: { type: Type.ARRAY, items: { type: Type.STRING } },
                                    peakActivityTime: { type: Type.STRING }
                                }
                            },
                            recommendations: { type: Type.ARRAY, items: { type: Type.STRING } }
                        },
                        required: ["summary", "anomalies", "threats", "errors", "statistics", "recommendations"],
                    },
                },
            });
            
            const jsonText = response.text.trim();
            const parsedResponse = JSON.parse(jsonText);
            
            const normalizeArray = (arr) => {
                if (!Array.isArray(arr)) return [];
                return arr.map(item => {
                    if (typeof item === 'string') return item;
                    if (typeof item === 'object' && item !== null) {
                        return item.description || item.text || item.message || JSON.stringify(item);
                    }
                    return String(item);
                });
            };
            
            const normalizedResponse = {
                ...parsedResponse,
                anomalies: normalizeArray(parsedResponse.anomalies),
                threats: normalizeArray(parsedResponse.threats),
                errors: normalizeArray(parsedResponse.errors),
                recommendations: normalizeArray(parsedResponse.recommendations)
            };
            
            logger.info('Gemini AI analysis completed successfully');
            res.json(normalizedResponse);
        } catch (error) {
            logger.error("Gemini API Error:", error);
            res.status(500).json({ error: `Failed to get analysis from Gemini. ${error.message || ''}` });
        }
    } else if (aiProvider === 'ollama') {
        const urlToUse = ollamaUrl || config.ai.ollama.baseUrl;
        if (!urlToUse) {
            return res.status(400).json({ error: 'Ollama server URL is not configured.' });
        }
        try {
            const prompt = `You are an expert Postfix mail server administrator and security analyst. Analyze these Postfix mail logs and provide a detailed JSON response.

Logs to analyze:
${logs}

Provide a comprehensive JSON analysis with this exact structure:
{
  "summary": "A detailed 3-5 paragraph executive summary covering overall mail server health, mail flow patterns, delivery rates, concerning trends, and recommendations",
  "anomalies": ["List specific unusual patterns with examples from logs"],
  "threats": ["List potential security threats with specific evidence from logs"],
  "errors": ["List configuration and operational errors with specific SMTP codes and details"],
  "statistics": {
    "totalMessages": "count",
    "successRate": "percentage",
    "bounceRate": "percentage",
    "deferredRate": "percentage",
    "topSenderDomains": ["domain list"],
    "topRecipientDomains": ["domain list"],
    "peakActivityTime": "time period"
  },
  "recommendations": ["List actionable improvements"]
}

Be specific, cite log entries, identify patterns, and prioritize by severity. Return ONLY valid JSON.`;

            const ollamaResponse = await fetch(`${urlToUse}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: config.ai.ollama.model,
                    prompt: prompt,
                    format: 'json',
                    stream: false,
                    options: {
                        temperature: 0.7,
                        top_p: 0.9,
                        num_predict: 2000
                    }
                }),
            });

            if (!ollamaResponse.ok) {
                const errorBody = await ollamaResponse.text();
                throw new Error(`Ollama server returned an error: ${ollamaResponse.status} ${errorBody}`);
            }

            const ollamaData = await ollamaResponse.json();
            const parsedResponse = JSON.parse(ollamaData.response);
            
            const normalizeArray = (arr) => {
                if (!Array.isArray(arr)) return [];
                return arr.map(item => {
                    if (typeof item === 'string') return item;
                    if (typeof item === 'object' && item !== null) {
                        return item.description || item.text || item.message || JSON.stringify(item);
                    }
                    return String(item);
                });
            };
            
            const validatedResponse = {
                summary: parsedResponse.summary || 'No summary provided',
                anomalies: normalizeArray(parsedResponse.anomalies),
                threats: normalizeArray(parsedResponse.threats),
                errors: normalizeArray(parsedResponse.errors),
                statistics: parsedResponse.statistics || {
                    totalMessages: 'N/A',
                    successRate: 'N/A',
                    bounceRate: 'N/A',
                    deferredRate: 'N/A',
                    topSenderDomains: [],
                    topRecipientDomains: [],
                    peakActivityTime: 'N/A'
                },
                recommendations: normalizeArray(parsedResponse.recommendations)
            };
            
            logger.info('Ollama AI analysis completed successfully');
            res.json(validatedResponse);
        } catch (error) {
            logger.error("Ollama Error:", error);
            res.status(500).json({ error: `Failed to get analysis from Ollama. Check if the server is running and accessible. ${error.message || ''}` });
        }
    } else {
        res.status(400).json({ error: 'Invalid AI provider specified.' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        ai: {
            gemini: !!ai,
            ollama: config.ai.ollama.baseUrl,
        },
    });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Backend server is running on http://localhost:${PORT}`);
  logger.info(`Token expiry: ${config.auth.tokenExpiryHours} hours`);
  logger.info(`AI Provider: ${config.ai.provider}`);
  logger.info(`Log Level: ${config.server.logLevel}`);
});
