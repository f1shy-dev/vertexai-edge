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
import { GenerateContentRequest, GenerateContentResult, GenerationConfig, RequestOptions, SafetySetting, StreamGenerateContentResult, Tool } from '../types/content';
import { ToolConfig } from '../types/tool';
/**
 * Make a async call to generate content.
 * @param request A GenerateContentRequest object with the request contents.
 * @returns The GenerateContentResponse object with the response candidates.
 */
export declare function generateContent(location: string, resourcePath: string, token: Promise<string | null | undefined>, request: GenerateContentRequest | string, apiEndpoint?: string, generationConfig?: GenerationConfig, safetySettings?: SafetySetting[], tools?: Tool[], toolConfig?: ToolConfig, requestOptions?: RequestOptions): Promise<GenerateContentResult>;
/**
 * Make an async stream request to generate content. The response will be
 * returned in stream.
 * @param {GenerateContentRequest} request - {@link GenerateContentRequest}
 * @returns {Promise<StreamGenerateContentResult>} Promise of {@link
 *     StreamGenerateContentResult}
 */
export declare function generateContentStream(location: string, resourcePath: string, token: Promise<string | null | undefined>, request: GenerateContentRequest | string, apiEndpoint?: string, generationConfig?: GenerationConfig, safetySettings?: SafetySetting[], tools?: Tool[], toolConfig?: ToolConfig, requestOptions?: RequestOptions): Promise<StreamGenerateContentResult>;
