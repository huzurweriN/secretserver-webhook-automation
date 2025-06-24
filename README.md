# 🔐 SecretServer Webhook Automation

A lightweight and secure Node.js webhook service that automates secret creation and permission assignment using the SecretServer REST API.

## 🚀 Features

- 📥 Trigger secret creation via incoming webhook
- 🧱 Configure secrets using template, site, and folder IDs
- 🔒 Assign user permissions (domain-based access)
- 🛡️ Optional: bind privileged accounts and apply secret policies
- 🩺 Built-in health check endpoint
- ⚠️ Winston-based structured logging and rate-limiting for protection

## 📦 Installation

```bash
git clone https://github.com/huzurwerin/secretserver-webhook-automation.git
cd secretserver-webhook-automation
npm install
```

## ⚙️ Environment Variables

Create a `.env` file in your root directory with the following content:

```env
PORT=3000
NODE_ENV=production
SECRETSERVER_API_URL=https://your.secretserver.url/api/v1
SECRETSERVER_API_TOKEN=your_api_token_here
```

## 📡 API Endpoints

### 🔹 POST `/webhook`

Create a secret and assign permissions automatically.

#### Example Request Body:
```json
{
  "secretName": "MyApp_Admin",
  "templateId": 11,
  "siteId": 1,
  "folderId": 3,
  "domain": "example.local",
  "username1": "admin-user",
  "username2": "j.doe",
  "password": "MySecurePass123!",
  "secretAccessRoleName": "ReadOnly",
  "secretPolicyId": 100,
  "privilegedAccountSecretId": 250
}
```

### 🔹 GET `/health`

Basic service health check.

Returns:
```json
{ "status": "OK", "timestamp": "..." }
```

## 🧾 Logging

- `combined.log`: all requests
- `error.log`: failed or rejected operations
- Console output for development

## 🛡️ Security

- HTTP header protection with Helmet
- Brute-force protection with rate limiting
- Input validation using express-validator
- Optional SSL verification disabling for test environments

## 🤝 Contributing

Pull requests are welcome. Feel free to open issues for bugs or suggestions.

## 🪪 License

MIT License. See the LICENSE file for more information.

> 📌 Note: This is an open-source personal project and contains no real credentials.
