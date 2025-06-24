const express = require('express');
const axios = require('axios');
const https = require('https');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'secretserver-webhook' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

const app = express();
const port = process.env.PORT || 3000;

// Security Middleware
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Validation
const validateWebhookInput = [
  body('secretName').notEmpty().withMessage('Secret name is required'),
  body('templateId').isNumeric().withMessage('Valid template ID is required'),
  body('siteId').isNumeric().withMessage('Valid site ID is required'),
  body('folderId').isNumeric().withMessage('Valid folder ID is required'),
  body('domain').optional(),
  body('username1').notEmpty().withMessage('Username is required for secret creation'),
  body('username2').notEmpty().withMessage('Username is required for permission'),
  body('password').optional(),
  body('secretAccessRoleName').notEmpty().withMessage('Secret access role name is required'),
  body('secretPolicyId').custom((value, { req }) => {
    if (req.body.domain === 'example.com' && !value) {
      throw new Error('secretPolicyId is required for example.com domain');
    }
    return true;
  }),
  body('privilegedAccountSecretId').optional().isNumeric().withMessage('Valid privileged account secret ID is required if provided'),
];

// SecretServer API Service
class SecretServerService {
  constructor() {
    this.apiUrl = process.env.SECRETSERVER_API_URL;
    this.token = process.env.SECRETSERVER_API_TOKEN;

    if (!this.apiUrl || !this.token) {
      throw new Error('Missing SecretServer API configuration');
    }

    this.axiosInstance = process.env.NODE_ENV === 'test'
      ? axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) })
      : axios.create();
  }

  getHeaders() {
    return {
      Authorization: `Bearer ${this.token}`,
      'Content-Type': 'application/json',
    };
  }

  async getSecretStub(templateId) {
    try {
      const response = await this.axiosInstance.get(
        `${this.apiUrl}/secrets/stub?filter.secrettemplateid=${templateId}`,
        { headers: this.getHeaders() }
      );
      return response.data;
    } catch (error) {
      logger.error('Failed to get secret stub', {
        error: error.response?.data || error.message,
        templateId
      });
      throw new Error(`Failed to get secret stub: ${error.message}`);
    }
  }

  async createSecret(secretStub) {
    try {
      const response = await this.axiosInstance.post(
        `${this.apiUrl}/secrets/`,
        secretStub,
        { headers: this.getHeaders() }
      );
      return response.data;
    } catch (error) {
      if (error.response?.data?.errorCode === 'API_PriviledgedSecretPermissionRequiredValidationFail') {
        throw new Error('Insufficient permissions: Required Secret Policy permission is missing');
      }
      logger.error('Failed to create secret', {
        error: error.response?.data || error.message,
        secretName: secretStub.name
      });
      throw new Error(`Failed to create secret: ${error.message}`);
    }
  }

  async updateInheritPermissions(secretId) {
    try {
      const payload = {
        data: {
          inheritPermissions: {
            dirty: true,
            value: false,
          },
        },
      };
      await this.axiosInstance.patch(
        `${this.apiUrl}/secrets/${secretId}/share`,
        payload,
        { headers: this.getHeaders() }
      );
      return true;
    } catch (error) {
      logger.error('Failed to update inherit permissions', {
        error: error.response?.data || error.message,
        secretId
      });
      throw new Error(`Failed to update permissions: ${error.message}`);
    }
  }

  async setSecretPermissions(domainName, secretAccessRoleName, secretId, userName) {
    try {
      const payload = { domainName, secretAccessRoleName, secretId, userName };
      await this.axiosInstance.post(
        `${this.apiUrl}/secret-permissions`,
        payload,
        { headers: this.getHeaders() }
      );
      return true;
    } catch (error) {
      logger.error('Failed to set secret permissions', {
        error: error.response?.data || error.message,
        secretId,
        userName
      });
      throw new Error(`Failed to set permissions: ${error.message}`);
    }
  }

  async setPrivilegedAccount(privilegedAccountSecretId, secretId) {
    try {
      const payload = {
        data: {
          privilegedAccountSecretId,
          secretIds: [secretId],
        },
      };
      await this.axiosInstance.post(
        `${this.apiUrl}/bulk-secret-operations/set-privileged-account`,
        payload,
        { headers: this.getHeaders() }
      );
      return true;
    } catch (error) {
      logger.error('Failed to set privileged account', {
        error: error.response?.data || error.message,
        secretId,
        privilegedAccountSecretId
      });
      throw new Error(`Failed to set privileged account: ${error.message}`);
    }
  }
}

const secretServerService = new SecretServerService();

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/webhook', validateWebhookInput, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const {
      secretName,
      templateId,
      siteId,
      folderId,
      domain,
      username1,
      username2,
      password,
      secretAccessRoleName,
      secretPolicyId,
      privilegedAccountSecretId,
    } = req.body;

    logger.info('Processing webhook request', {
      secretName,
      templateId,
      domain,
      requestId: req.id
    });

    const secretStub = await secretServerService.getSecretStub(templateId);

    secretStub.name = secretName;
    secretStub.secretTemplateId = templateId;
    secretStub.autoChangeEnabled = false;
    secretStub.autoChangeNextPassword = password || '';
    secretStub.siteId = siteId;
    secretStub.folderId = folderId;
    secretStub.changePasswordNow = true;

    if (secretPolicyId) secretStub.secretPolicyId = secretPolicyId;

    secretStub.items.forEach((item) => {
      if (item.fieldName === 'Domain') item.itemValue = domain || '';
      if (item.fieldName === 'Username') item.itemValue = username1 || '';
      if (item.fieldName === 'Password') item.itemValue = password || '';
    });

    const createdSecret = await secretServerService.createSecret(secretStub);
    const secretId = createdSecret.id;

    logger.info('Secret created successfully', { secretId, secretName });

    await secretServerService.updateInheritPermissions(secretId);
    await secretServerService.setSecretPermissions(domain || '', secretAccessRoleName, secretId, username2);
    if (domain !== 'example.com' && privilegedAccountSecretId) {
      await secretServerService.setPrivilegedAccount(privilegedAccountSecretId, secretId);
    }

    return res.status(200).json({
      message: 'Secret created successfully and all operations completed',
      secretId,
    });
  } catch (error) {
    logger.error('Error processing webhook request', {
      error: error.message,
      stack: error.stack,
    });

    if (error.message.includes('Insufficient permissions')) {
      return res.status(403).json({ error: 'Permission denied', details: error.message });
    }

    return res.status(500).json({ error: 'Failed to process webhook request', details: error.message });
  }
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
  });
});

app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;
