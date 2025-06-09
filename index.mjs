/**
 * @file signup.js
 * @module signup
 * @description
 * AWS Lambda handler for user signup in ACS.
 * Supports two providers: "form" (email/password + reCAPTCHA) and "google" (OAuth).
 *
 * - FORM signups:
 *   • Verify CAPTCHA
 *   • Create Cognito user (suppressed invite)
 *   • Permanently set password
 *   • Authenticate via USER_PASSWORD_AUTH (InitiateAuthCommand)
 *   • Persist user & session to DynamoDB
 *   • Issue Cognito tokens + session cookie
 *
 * - GOOGLE signups:
 *   • Generate random password
 *   • Create Cognito user (suppressed invite) with email_verified=true
 *   • Permanently set password
 *   • Persist user & session to DynamoDB
 *   • Issue only session cookie
 *
 */

import crypto from "crypto";
import { DynamoDBClient, PutItemCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  InitiateAuthCommand,
  ListUsersCommand
} from "@aws-sdk/client-cognito-identity-provider";
import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

// ── CONFIG ────────────────────────────────────────────────────────────────
const REGION           = process.env.AWS_REGION      || "us-east-2";
const USER_POOL_ID     = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID        = process.env.COGNITO_CLIENT_ID;
const CLIENT_SECRET    = process.env.COGNITO_CLIENT_SECRET;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;

// Validate environment variables
if (!USER_POOL_ID || !CLIENT_ID || !CLIENT_SECRET || !RECAPTCHA_SECRET) {
  throw new Error(
    "Missing required env vars: COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, " +
    "COGNITO_CLIENT_SECRET, or RECAPTCHA_SECRET_KEY"
  );
}

// AWS SDK clients
const dynamoDb      = new DynamoDBClient({ region: REGION });
const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });
const lambdaClient  = new LambdaClient({ region: REGION });

/** @readonly @enum {string} Supported signup providers */
const PROVIDERS = {
  FORM:   "form",
  GOOGLE: "google",
};
const ALLOWED_PROVIDERS = Object.values(PROVIDERS);

/**
 * Compute Cognito SECRET_HASH for a given username.
 * Required when your App Client has a client secret.
 *
 * @param {string} username
 * @returns {string} Base64-encoded HMAC-SHA256(username + CLIENT_ID)
 */
function getSecretHash(username) {
  return crypto
    .createHmac("SHA256", CLIENT_SECRET)
    .update(username + CLIENT_ID)
    .digest("base64");
}

/**
 * Generate a strong random password for Google accounts.
 * @returns {string}
 */
function generateRandomPassword() {
  return (
    Math.random().toString(36).slice(-8) +
    Math.random().toString(36).toUpperCase().slice(-8) +
    "!"
  );
}

/**
 * Generate a unique session identifier.
 * @returns {string}
 */
function generateSessionId() {
  const timestamp = Date.now();
  const randomStr = Math.random().toString(36).substring(2, 10);
  return `${timestamp}-${randomStr}`;
}

/**
 * Persist a session record in DynamoDB.
 *
 * @param {string} uid           - User's unique ID (email).
 * @param {string} responseEmail - Generated internal response email.
 * @returns {Promise<string>}    - The new session ID.
 */
async function addSession(uid, responseEmail) {
  const sessionId = generateSessionId();
  const nowSec    = Math.floor(Date.now() / 1000);
  const ttl       = nowSec + 30 * 24 * 3600; // 30 days
  await dynamoDb.send(new PutItemCommand({
    TableName: "Sessions",
    Item: {
      session_id:     { S: sessionId },
      created_at:     { S: new Date().toISOString() },
      expiration:     { N: ttl.toString() },
      response_email: { S: responseEmail },
      user_id:        { S: uid },
    },
  }));
  return sessionId;
}

/**
 * Retrieve CORS headers by invoking helper Lambda.
 * Falls back to permissive defaults if the helper fails.
 *
 * @param {object} event - API Gateway event.
 * @returns {Promise<object>} CORS headers map.
 */
async function getCorsHeaders(event) {
  try {
    const res = await lambdaClient.send(new InvokeCommand({
      FunctionName:   "Allow-Cors",
      InvocationType: "RequestResponse",
      Payload:        JSON.stringify(event),
    }));
    const payload = JSON.parse(new TextDecoder().decode(res.Payload));
    return payload.headers;
  } catch {
    return {
      "Access-Control-Allow-Origin":      "*",
      "Access-Control-Allow-Methods":     "OPTIONS, POST",
      "Access-Control-Allow-Headers":     "Content-Type",
      "Access-Control-Allow-Credentials": "true",
    };
  }
}

/**
 * Verify a reCAPTCHA token via Google's siteverify API.
 *
 * @param {string} token - reCAPTCHA response from client.
 * @throws {object} On failure, with fields:
 *   - type: "missing_token"|"network_error"|"invalid_token"|"low_score"
 *   - message: human-readable description
 *   - codes?: string[] (when invalid_token)
 *   - score?: number  (when low_score)
 */
async function verifyCaptcha(token) {
  if (!token) {
    throw { type: "missing_token", message: "Captcha token is required" };
  }

  const params = new URLSearchParams({
    secret:   RECAPTCHA_SECRET,
    response: token,
  });

  const resp = await fetch(
    "https://www.google.com/recaptcha/api/siteverify",
    { method: "POST", body: params }
  );
  if (!resp.ok) {
    throw { type: "network_error", message: `Captcha request failed (${resp.status})` };
  }

  const body = await resp.json();
  if (!body.success) {
    throw {
      type:   "invalid_token",
      message:"Captcha verification failed",
      codes:  body["error-codes"] || []
    };
  }
  if (body.score !== undefined && body.score < 0.5) {
    throw {
      type:   "low_score",
      message:`Captcha score too low (${body.score})`,
      score:  body.score
    };
  }
}

/**
 * Generate a unique email by appending random digits if the base email exists.
 * @param {string} baseEmail - The base email to check
 * @returns {Promise<string>} - A unique email
 */
async function generateUniqueEmail(baseEmail) {
  const baseName = baseEmail.split('@')[0];
  const domain = baseEmail.split('@')[1];
  
  // Check if the base email exists
  const listResp = await dynamoDb.send(new ScanCommand({
    TableName: "Users",
    FilterExpression: "acsMail = :email",
    ExpressionAttributeValues: {
      ":email": { S: baseEmail }
    }
  }));

  if (!listResp.Items?.length) {
    return baseEmail;
  }

  // If exists, append random digits until we find a unique one
  let attempts = 0;
  let newEmail;
  do {
    const randomDigits = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    newEmail = `${baseName}${randomDigits}@${domain}`;
    
    const checkResp = await dynamoDb.send(new ScanCommand({
      TableName: "Users",
      FilterExpression: "acsMail = :email",
      ExpressionAttributeValues: {
        ":email": { S: newEmail }
      }
    }));
    
    attempts++;
    if (attempts > 10) {
      throw new Error("Failed to generate unique email after 10 attempts");
    }
  } while (listResp.Items?.length > 0);

  return newEmail;
}

/**
 * AWS Lambda handler for user signup.
 *
 * @param {object} event            - API Gateway event.
 * @param {string} event.httpMethod - "OPTIONS" or "POST".
 * @param {string} event.body       - JSON string with:
 *   { id, email, password?, name, captchaToken?, provider }
 * @returns {Promise<object>} API Gateway response.
 */
export const handler = async (event) => {
  const cors = await getCorsHeaders(event);

  // Preflight CORS
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: cors, body: "" };
  }

  // Parse + validate payload
  let id, email, password, name, captchaToken, provider;
  try {
    const b = JSON.parse(event.body || "{}");
    console.log("Payload received: ", b);
    ({ id, email, password, name, captchaToken, provider } = b);

    if (!id || !email || !name || !provider) {
      throw new Error("Missing required fields: id, email, name, or provider");
          }
    if (provider === PROVIDERS.FORM && !captchaToken) {
      throw new Error("Captcha token is required for form signup");
    }
    if (!ALLOWED_PROVIDERS.includes(provider)) {
      throw new Error(`Provider must be one of ${ALLOWED_PROVIDERS.join(", ")}`);
    }
    if (provider === PROVIDERS.FORM && !password) {
      throw new Error("Form signup requires a password");
    }
  } catch (err) {
    return {
      statusCode: 400,
      headers: cors,
      body: JSON.stringify({ message: `Invalid payload: ${err.message}` }),
    };
  }

  // Build internal response email
  const baseResponseEmail = `${name.replace(/\s+/g, "").toLowerCase()}@homes.automatedconsultancy.com`;
  const responseEmail = await generateUniqueEmail(baseResponseEmail);

  // Default email signature
  const defaultSignature = `Best Regards,\n${name}\n${email}`;

  // Verify CAPTCHA for FORM
  if (provider === PROVIDERS.FORM) {
    try {
      await verifyCaptcha(captchaToken);
    } catch (err) {
      const statusCode = ["missing_token","invalid_token"].includes(err.type) ? 400 : 429;
      return {
        statusCode,
        headers: cors,
        body: JSON.stringify({
          message: err.message,
          ...(err.codes && { errorCodes: err.codes }),
          ...(err.score !== undefined && { score: err.score }),
        }),
      };
    }
  }

  try {
    // Determine password
    const pwd = provider === PROVIDERS.FORM
      ? password
      : generateRandomPassword();

    // Construct Cognito attributes
    const userAttrs = [
      { Name: "email",           Value: email },
      { Name: "name",            Value: name },
      { Name: "custom:provider", Value: provider }
    ];
    // if (provider === PROVIDERS.GOOGLE) {
    
    //@TODO for now, we will set all verified emails to true.
    userAttrs.push({ Name: "email_verified", Value: "true" });
    // }
    
    // 0) Check if a user with this email already exists
    const listResp = await cognitoClient.send(new ListUsersCommand({
      UserPoolId: USER_POOL_ID,
      Filter: `email = "${email}"`,
      Limit: 1,
    }));
    if (listResp.Users?.length) {
      return {
        statusCode: 409,
        headers: cors,
        body: JSON.stringify({ message: "User already exists" }),
      };
    }

    // 1) Create Cognito user
    await cognitoClient.send(new AdminCreateUserCommand({
      UserPoolId:       USER_POOL_ID,
      Username:         id,
      TemporaryPassword:pwd,
      MessageAction:    "SUPPRESS",
      UserAttributes:   userAttrs,
    }));

    // 2) Set permanent password
    await cognitoClient.send(new AdminSetUserPasswordCommand({
      UserPoolId: USER_POOL_ID,
      Username:   id,
      Password:   pwd,
      Permanent:  true,
    }));

    // 3) Persist user in DynamoDB
    const uid = id;
    await dynamoDb.send(new PutItemCommand({
      TableName: "Users",
      Item: {
        id:            { S: uid },
        email:         { S: email },
        responseEmail: { S: responseEmail },
        acsMail:       { S: responseEmail },
        provider:      { S: provider },
        createdAt:     { S: new Date().toISOString() },
        role:          { S: "user" },
        email_signature: { S: defaultSignature }
      },
    }));

    console.log("Calling InitiateAuth with USERNAME:", id);
    console.log("CLIENT_ID:", CLIENT_ID);
    console.log(
      "Computed SecretHash:",
      getSecretHash(id)
    );


    // 4) Authenticate FORM users and build cookies
    let cookies;
    if (provider === PROVIDERS.FORM) {
      // Use InitiateAuthCommand with USER_PASSWORD_AUTH
      const auth = await cognitoClient.send(new InitiateAuthCommand({
        AuthFlow:       "USER_PASSWORD_AUTH",
        ClientId:       CLIENT_ID,
        AuthParameters: {
          USERNAME:    id,
          PASSWORD:    pwd,
          SECRET_HASH: getSecretHash(id),
        },
      }));
      const tokens = auth.AuthenticationResult;
      if (!tokens) throw new Error("Auth flow failed");

      const sessionId = await addSession(uid, responseEmail);
      cookies = [
        `session_id=${sessionId}; HttpOnly; Secure; SameSite=None; Max-Age=2592000`,
        `id_token=${tokens.IdToken}; HttpOnly; Secure; SameSite=None; Max-Age=3600`,
        `access_token=${tokens.AccessToken}; HttpOnly; Secure; SameSite=None; Max-Age=3600`,
        `refresh_token=${tokens.RefreshToken}; HttpOnly; Secure; SameSite=None; Max-Age=1209600`,
      ].join(",");
    } else {
      // GOOGLE users only get session cookie
      const sessionId = await addSession(uid, responseEmail);
      cookies = `session_id=${sessionId}; HttpOnly; Secure; SameSite=None; Max-Age=2592000`;
    }

    // 5) Return success
    return {
      statusCode: 201,
      headers: { ...cors, "Set-Cookie": cookies, "Content-Type": "application/json" },
      body: JSON.stringify({
        message: provider === PROVIDERS.FORM
          ? "User created & signed in"
          : "Google user created & signed in",
        authtype: "new"
      }),
    };

  } catch (err) {
    console.error("Signup error:", err);
    const conflict = err.name === "UsernameExistsException";
    return {
      statusCode: conflict ? 409 : 500,
      headers: cors,
      body: JSON.stringify({ message: err.message }),
    };
  }
};
