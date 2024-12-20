/**
 * @license
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * GoogleAuthError is thrown when there is authentication issue with the request
 */
declare class GoogleAuthError extends Error {
    readonly stackTrace?: Error;
    constructor(message: string, stackTrace?: Error);
}
/**
 * ClientError is thrown when http 4XX status is received.
 * For details please refer to https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#client_error_responses
 */
declare class ClientError extends Error {
    readonly stackTrace?: Error;
    constructor(message: string, stackTrace?: Error);
}
/**
 * Google API Error Details object that may be included in an error response.
 * See https://cloud.google.com/apis/design/errors
 * @public
 */
export declare interface ErrorDetails {
    '@type'?: string;
    reason?: string;
    domain?: string;
    metadata?: Record<string, unknown>;
    [key: string]: unknown;
}
/**
 * GoogleApiError is thrown when http 4XX status is received.
 * See https://cloud.google.com/apis/design/errors
 */
declare class GoogleApiError extends Error {
    code?: number | undefined;
    status?: string | undefined;
    errorDetails?: ErrorDetails[] | undefined;
    constructor(message: string, code?: number | undefined, status?: string | undefined, errorDetails?: ErrorDetails[] | undefined);
}
/**
 * GoogleGenerativeAIError is thrown when http response is not ok and status code is not 4XX
 * For details please refer to https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
 */
declare class GoogleGenerativeAIError extends Error {
    readonly stackTrace?: Error;
    constructor(message: string, stackTrace?: Error);
}
/**
 * IllegalArgumentError is thrown when the request or operation is invalid
 */
declare class IllegalArgumentError extends Error {
    readonly stackTrace?: Error;
    constructor(message: string, stackTrace?: Error);
}
export { ClientError, GoogleApiError, GoogleAuthError, GoogleGenerativeAIError, IllegalArgumentError, };
