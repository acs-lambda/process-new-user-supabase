import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

// Configure logging
const logger = {
  info: (...args) => console.log("[INFO]", ...args),
  error: (...args) => console.error("[ERROR]", ...args),
  warning: (...args) => console.warn("[WARN]", ...args)
};

// Initialize AWS clients
const lambdaClient = new LambdaClient({ region: process.env.AWS_REGION || "us-east-2" });
const dynamoDb = new DynamoDBClient({ region: process.env.AWS_REGION || "us-east-2" });

/**
 * Custom error class for authorization failures
 */
export class AuthorizationError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthorizationError";
  }
}

/**
 * Invoke a Lambda function by name with the given payload
 * @param {string} functionName - Name of the Lambda function to invoke
 * @param {Object} payload - Payload to send to the Lambda function
 * @returns {Promise<Object>} Response from the Lambda function
 * @throws {Error} If Lambda invocation fails
 */
export async function invoke(functionName, payload) {
  try {
    const command = new InvokeCommand({
      FunctionName: functionName,
      InvocationType: "RequestResponse",
      Payload: JSON.stringify(payload)
    });

    const response = await lambdaClient.send(command);
    const responsePayload = JSON.parse(new TextDecoder().decode(response.Payload));

    if (response.FunctionError) {
      logger.error(`Lambda function ${functionName} returned an error:`, responsePayload);
      throw new Error(responsePayload.errorMessage || "Unknown error");
    }

    return responsePayload;
  } catch (error) {
    logger.error(`Failed to invoke Lambda function ${functionName}:`, error);
    throw error;
  }
}

/**
 * Parse an event from either API Gateway or direct Lambda invocation
 * @param {Object} event - The event to parse, either from API Gateway or direct Lambda
 * @returns {Object} Parsed event data including body and cookies if present
 * @throws {Error} If event parsing fails
 */
export function parseEvent(event) {
  try {
    const parsedData = {};

    // Check if this is an API Gateway event
    if ('body' in event) {
      // Parse the body if it's a string
      if (typeof event.body === 'string') {
        try {
          Object.assign(parsedData, JSON.parse(event.body));
        } catch {
          // If body is not JSON, use it as is
          parsedData.body = event.body;
        }
      } else {
        Object.assign(parsedData, event.body);
      }

      // Handle cookies from API Gateway
      if (event.headers?.Cookie) {
        const cookies = event.headers.Cookie;
        // Parse cookies into a dictionary
        const cookieDict = Object.fromEntries(
          cookies.split('; ').map(cookie => cookie.split('=', 2))
        );
        Object.assign(parsedData, cookieDict);
      }
    } else {
      // Direct Lambda invocation - use event as is
      Object.assign(parsedData, event);
    }

    return parsedData;
  } catch (error) {
    logger.error("Error parsing event:", error);
    throw error;
  }
}

/**
 * Authorize a user by validating their session
 * @param {string} userId - The user ID to validate
 * @param {string} sessionId - The session ID to validate
 * @returns {Promise<void>}
 * @throws {AuthorizationError} If authorization fails
 */
export async function authorize(userId, sessionId) {
  try {
    if (!sessionId) {
      throw new AuthorizationError("No session ID provided");
    }

    // Query the Sessions table
    const command = new GetItemCommand({
      TableName: "Sessions",
      Key: { session_id: { S: sessionId } }
    });

    const response = await dynamoDb.send(command);
    const session = response.Item ? unmarshall(response.Item) : null;

    if (!session) {
      logger.warning(`Session not found: ${sessionId}`);
      throw new AuthorizationError("ACS: Unauthorized");
    }

    // Validate user_id matches session
    if (session.associated_account !== userId) {
      logger.warning(`User ID mismatch: ${userId} != ${session.associated_account}`);
      throw new AuthorizationError("ACS: Unauthorized");
    }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      throw error;
    }
    logger.error("Error during authorization:", error);
    throw new AuthorizationError("ACS: Unauthorized");
  }
} 