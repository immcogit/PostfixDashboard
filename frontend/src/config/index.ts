// ============================================
// FILE: frontend/src/config/index.ts
// ============================================
// Path: postfix-dashboard/frontend/src/config/index.ts

// Centralized configuration
const config = {
  api: {
    // In development, use empty string to use Vite's proxy
    // In production, set VITE_API_BASE_URL to your backend URL
    baseUrl: import.meta.env.VITE_API_BASE_URL || '',
    timeout: parseInt(import.meta.env.VITE_API_TIMEOUT || '30000'),
  },
  auth: {
    tokenKey: 'postfix_auth_token',
    tokenExpiryKey: 'postfix_token_expiry',
    expiryHours: parseInt(import.meta.env.VITE_TOKEN_EXPIRY_HOURS || '24'),
  },
  app: {
    name: import.meta.env.VITE_APP_NAME || 'Postfix Dashboard',
    version: import.meta.env.VITE_APP_VERSION || '2.2.0',
  },
  pagination: {
    defaultPageSize: 50,
    pageSizeOptions: [25, 50, 100, 200],
  },
} as const;

export { config };

export default config;
