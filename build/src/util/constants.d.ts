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
export declare const GENERATE_CONTENT_METHOD = "generateContent";
export declare const STREAMING_GENERATE_CONTENT_METHOD = "streamGenerateContent";
export declare const COUNT_TOKENS_METHOD = "countTokens";
export declare const USER_ROLE = "user";
export declare const MODEL_ROLE = "model";
export declare const SYSTEM_ROLE = "system";
export declare const USER_AGENT = "model-builder/1.9.0 grpc-node/1.9.0";
export declare const CREDENTIAL_ERROR_MESSAGE = "\nUnable to authenticate your request        \nDepending on your run time environment, you can get authentication by        \n- if in local instance or cloud shell: `!gcloud auth login`        \n- if in Colab:        \n    -`from google.colab import auth`        \n    -`auth.authenticate_user()`        \n- if in service account or other: please follow guidance in https://cloud.google.com/docs/authentication";
