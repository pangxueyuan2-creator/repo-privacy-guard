export const SEVERITY_ORDER = Object.freeze({
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
});

export const SECRET_PATTERNS = Object.freeze([
  {
    id: "openai-api-key",
    severity: "critical",
    message: "Possible OpenAI API key",
    source: String.raw`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`,
    flags: "g",
  },
  {
    id: "github-token",
    severity: "critical",
    message: "Possible GitHub access token",
    source: String.raw`\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b`,
    flags: "g",
  },
  {
    id: "aws-access-key",
    severity: "critical",
    message: "Possible AWS access key ID",
    source: String.raw`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
    flags: "g",
  },
  {
    id: "google-api-key",
    severity: "high",
    message: "Possible Google API key",
    source: String.raw`\bAIza[0-9A-Za-z_-]{30,}\b`,
    flags: "g",
  },
  {
    id: "slack-token",
    severity: "critical",
    message: "Possible Slack token",
    source: String.raw`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`,
    flags: "g",
  },
  {
    id: "private-key",
    severity: "critical",
    message: "Private key header",
    source: String.raw`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`,
    flags: "g",
  },
  {
    id: "credentialed-url",
    severity: "critical",
    message: "Connection URL appears to contain a password",
    source: String.raw`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s/:]+:[^\s@/]+@[^\s]+`,
    flags: "gi",
  },
  {
    id: "jwt",
    severity: "high",
    message: "Possible JSON Web Token",
    source: String.raw`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
    flags: "g",
  },
]);

export const PERSONAL_DATA_PATTERNS = Object.freeze([
  {
    id: "email-address",
    severity: "low",
    message: "Email address",
    source: String.raw`\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`,
    flags: "gi",
  },
  {
    id: "international-phone",
    severity: "low",
    message: "Possible international phone number",
    source: String.raw`(?<!\d)\+[1-9]\d{7,14}(?!\d)`,
    flags: "g",
  },
]);

export const SENSITIVE_FILE_PATTERNS = Object.freeze([
  { id: "environment-file", severity: "high", pattern: /(^|\/)\.env(?:\.|$)/i },
  { id: "private-key-file", severity: "critical", pattern: /(^|\/)(?:id_rsa|id_ed25519|.*\.(?:pem|p12|pfx|key))$/i },
  { id: "credential-file", severity: "high", pattern: /(^|\/)(?:credentials?|service-account)(?:\.[^/]*)?$/i },
  { id: "npm-auth-file", severity: "high", pattern: /(^|\/)\.npmrc$/i },
]);

export function isAtLeastSeverity(severity, minimum) {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum];
}
