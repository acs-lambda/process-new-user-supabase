/**
 * @file process-new-user-supabase.mjs
 * @module ProcessNewUserSupabase
 * @description
 * AWS Lambda handler for user signup in ACS.
 * Supports two providers: "form" (email/password + reCAPTCHA) and "google" (OAuth).
 * 
 * Payload Format:
 * {
 *   id: string,           // Required: User's unique identifier
 *   email: string,        // Required: User's email address
 *   name: string,         // Required: User's full name
 *   provider: string,     // Required: "form" or "google"
 *   password?: string,    // Required for "form" provider
 *   captchaToken?: string // Required for "form" provider
 * }
 * 
 * Functionality:
 * - FORM signups:
 *   • Verify CAPTCHA
 *   • Create Cognito user (suppressed invite)
 *   • Permanently set password
 *   • Authenticate via USER_PASSWORD_AUTH
 *   • Create session via CreateNewSession Lambda
 *   • Issue Cognito tokens + session cookie
 * 
 * - GOOGLE signups:
 *   • Generate random password
 *   • Create Cognito user (suppressed invite) with email_verified=true
 *   • Permanently set password
 *   • Create session via CreateNewSession Lambda
 *   • Issue only session cookie
 * 
 * Return Codes:
 * 200: Success - User created and signed in
 * 201: Success - User created and signed in (alternative success code)
 * 400: Bad Request - Missing required fields or invalid payload
 * 401: Unauthorized - CAPTCHA verification failed
 * 409: Conflict - User already exists
 * 429: Too Many Requests - CAPTCHA score too low
 * 500: Internal Server Error - Server-side error occurred
 * 
 * Response Format:
 * Success (200/201):
 * {
 *   message: string,      // Success message
 *   authType: string,     // "new" or "existing"
 *   headers: {
 *     "Set-Cookie": string[] // Array of cookies for FORM, single cookie for GOOGLE
 *   }
 * }
 * 
 * Error (400/401/409/429/500):
 * {
 *   message: string,      // Error description
 *   errorCodes?: string[], // For CAPTCHA errors
 *   score?: number        // For CAPTCHA score errors
 * }
 * 
 * Cookies:
 * - FORM signup: session_id, id_token, access_token, refresh_token
 * - GOOGLE signup: session_id only
 * 
 * All cookies are:
 * - HttpOnly
 * - Secure
 * - SameSite=None
 * - Max-Age=2592000 (30 days) for session_id
 * - Max-Age=3600 (1 hour) for id_token and access_token
 * - Max-Age=1209600 (14 days) for refresh_token
 */

import { createResponse, LambdaError, parseEvent } from './utils.mjs';
import { processNewUser } from './user_processor.mjs';

export const handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return createResponse(200, "", {
        "Access-Control-Allow-Methods": "OPTIONS, POST",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Credentials": "true",
      });
    }

    const payload = await parseEvent(event);
    
    const { id, email, name, provider, password, captchaToken } = payload;
    if (!id || !email || !name || !provider) {
        throw new LambdaError("Missing required fields: id, email, name, or provider", 400);
    }
    if (provider === "form" && (!password || !captchaToken)) {
        throw new LambdaError("Password and captcha token are required for form signup", 400);
    }

    const result = await processNewUser({ id, email, password, name, captchaToken, provider });

    return createResponse(201, { message: result.message, authType: result.authType }, { "Set-Cookie": result.cookies.join(',') });

  } catch (error) {
    console.error("Signup error:", error);
    const statusCode = error instanceof LambdaError ? error.statusCode : 500;
    return createResponse(statusCode, { message: error.message });
  }
};
