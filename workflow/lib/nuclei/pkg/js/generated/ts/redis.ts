

/**
 * Connect tries to connect redisdb server with password
 * @example
 * ```javascript
 * const redisdb = require('nuclei/redisdb');
 * const connected = redisdb.Connect('acme.com', 6379, 'password');
 * ```
 */
export function Connect(host: string, port: number, password: string): boolean | null {
    return null;
}



/**
 * GetServerInfo returns the server info for a redisdb server
 * @example
 * ```javascript
 * const redisdb = require('nuclei/redisdb');
 * const info = redisdb.GetServerInfo('acme.com', 6379);
 * ```
 */
export function GetServerInfo(host: string, port: number): string | null {
    return null;
}



/**
 * GetServerInfoAuth returns the server info for a redisdb server
 * @example
 * ```javascript
 * const redisdb = require('nuclei/redisdb');
 * const info = redisdb.GetServerInfoAuth('acme.com', 6379, 'password');
 * ```
 */
export function GetServerInfoAuth(host: string, port: number, password: string): string | null {
    return null;
}



/**
 * IsAuthenticated checks if the redisdb server requires authentication
 * @example
 * ```javascript
 * const redisdb = require('nuclei/redisdb');
 * const isAuthenticated = redisdb.IsAuthenticated('acme.com', 6379);
 * ```
 */
export function IsAuthenticated(host: string, port: number): boolean | null {
    return null;
}



/**
 * RunLuaScript runs a lua script on the redisdb server
 * @example
 * ```javascript
 * const redisdb = require('nuclei/redisdb');
 * const result = redisdb.RunLuaScript('acme.com', 6379, 'password', 'return redisdb.call("get", KEYS[1])');
 * ```
 */
export function RunLuaScript(host: string, port: number, password: string, script: string): any | null {
    return null;
}

