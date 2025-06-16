// Environment variables
export const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// Supabase
export const SUPABASE_URL = process.env.SUPABASE_URL;
export const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('Supabase URL and Key must be provided.');
  throw new Error('Supabase URL and Key must be provided.');
} 