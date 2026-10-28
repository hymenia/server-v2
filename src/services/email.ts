import nodemailer from "npm:nodemailer";

const SMTP_HOST = Deno.env.get("SMTP_HOST");
const SMTP_PORT = Number(Deno.env.get("SMTP_PORT") ?? "587");
const SMTP_USER = Deno.env.get("SMTP_USER");
const SMTP_PASS = Deno.env.get("SMTP_PASS");
const SMTP_SENDER = Deno.env.get("SMTP_SENDER");
const PUBLIC_BASE_URL = Deno.env.get("PUBLIC_BASE_URL");

function required(value: string | undefined, name: string): string {
  if (!value?.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value.trim();
}

function getConfig() {
  const host = required(SMTP_HOST, "SMTP_HOST");
  const user = required(SMTP_USER, "SMTP_USER");
  const pass = required(SMTP_PASS, "SMTP_PASS");
  const from = required(SMTP_SENDER, "SMTP_SENDER");
  const baseUrl = required(PUBLIC_BASE_URL, "PUBLIC_BASE_URL");

  if (![587, 465].includes(SMTP_PORT)) {
    throw new Error("SMTP_PORT must be 587 or 465");
  }

  const url = new URL(baseUrl);

  if (url.protocol !== "https:" && url.hostname !== "localhost") {
    throw new Error("PUBLIC_BASE_URL must use HTTPS");
  }

  return { host, user, pass, from, baseUrl: url.origin };
}

const config = getConfig();

const transporter = nodemailer.createTransport({
  host: config.host,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  requireTLS: SMTP_PORT === 587,
  auth: {
    user: config.user,
    pass: config.pass,
  },
  tls: {
    minVersion: "TLSv1.2",
    rejectUnauthorized: true,
  },
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 20_000,
});

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );

  return bytesToHex(new Uint8Array(digest));
}

export async function sendVerificationEmail(
  email: string,
  token: string,
): Promise<void> {
  const verificationUrl = new URL(
    "/api/v2/auth/verify-email",
    config.baseUrl,
  );

  verificationUrl.searchParams.set("token", token);

  await transporter.sendMail({
    from: config.from,
    to: email,
    subject: "Verify your Hymenia email address",
    text: [
      "Verify your email address for Hymenia.",
      "",
      `Open this link to verify your email: ${verificationUrl}`,
      "",
      "This link expires in 30 minutes and can only be used once.",
      "If you didn't create this account, you can ignore this email.",
    ].join("\n"),
    html: `
        <h1>Welcome to Hymenia</h1>
      <p>Verify your email address for Hymenia!</p>
      <p>
        <a href="${verificationUrl.toString()}">
          Verify email address
        </a>
      </p>
      <p>This link expires in 30 minutes and can only be used once.</p>
      <i>If you didn't create this account, you can ignore this email.</i>
    `,
  });
}

export async function createEmailVerification(
  sql: any,
  userId: string,
  email: string,
): Promise<void> {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToHex(tokenBytes);
  const tokenHash = await hashToken(token);

  // replace any tokens
  await sql.begin(async (tx: any) => {
    await tx`
      DELETE FROM email_verification_tokens
      WHERE user_id = ${userId}::uuid
    `;

    await tx`
      INSERT INTO email_verification_tokens
        (user_id, token_hash, expires_at)
      VALUES (
        ${userId}::uuid,
        ${tokenHash},
        NOW() + INTERVAL '30 minutes'
      )
    `;
  });

  // if delivery fails they can send another request to send the email
  await sendVerificationEmail(email, token);
}

/**
 * verify an email address using a token
 * returns true only if a valid token was used and the account updated
 */
export async function verifyEmail(
  sql: any,
  token: string,
): Promise<boolean> {
  // the token is 32 random bytes encoded as 64 hex characters
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return false;
  }

  const tokenHash = await hashToken(token);

  return await sql.begin(async (tx: any) => {
    const consumed = await tx`
      DELETE FROM email_verification_tokens
      WHERE token_hash = ${tokenHash}
        AND expires_at > NOW()
      RETURNING user_id
    `;

    if (consumed.length !== 1) {
      return false;
    }

    const userId = consumed[0].user_id;

    const updated = await tx`
      UPDATE users
      SET email_verified_at = NOW(),
          updated_at = NOW()
      WHERE id = ${userId}::uuid
        AND email IS NOT NULL
      RETURNING id
    `;

    if (updated.length !== 1) {
      throw new Error("Verification account update failed");
    }

    return true;
  });
}


export async function verifySmtpConnection(): Promise<void> {
  await transporter.verify();
}