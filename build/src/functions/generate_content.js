"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateContentStream = exports.generateContent = void 0;
const errors_1 = require("../types/errors");
const constants = require("../util/constants");
const post_fetch_processing_1 = require("./post_fetch_processing");
const post_request_1 = require("./post_request");
const pre_fetch_processing_1 = require("./pre_fetch_processing");
/**
 * Make a async call to generate content.
 * @param request A GenerateContentRequest object with the request contents.
 * @returns The GenerateContentResponse object with the response candidates.
 */
async function generateContent(location, resourcePath, token, request, apiEndpoint, generationConfig, safetySettings, tools, toolConfig, requestOptions) {
    var _a, _b, _c, _d;
    request = (0, pre_fetch_processing_1.formatContentRequest)(request, generationConfig, safetySettings);
    (0, pre_fetch_processing_1.validateGenerateContentRequest)(request);
    if (request.generationConfig) {
        request.generationConfig = (0, pre_fetch_processing_1.validateGenerationConfig)(request.generationConfig);
    }
    const generateContentRequest = {
        contents: request.contents,
        systemInstruction: request.systemInstruction,
        cachedContent: request.cachedContent,
        generationConfig: (_a = request.generationConfig) !== null && _a !== void 0 ? _a : generationConfig,
        safetySettings: (_b = request.safetySettings) !== null && _b !== void 0 ? _b : safetySettings,
        tools: (_c = request.tools) !== null && _c !== void 0 ? _c : tools,
        toolConfig: (_d = request.toolConfig) !== null && _d !== void 0 ? _d : toolConfig,
    };
    const response = await (0, post_request_1.postRequest)({
        region: location,
        resourcePath,
        resourceMethod: constants.GENERATE_CONTENT_METHOD,
        token: await token,
        data: generateContentRequest,
        apiEndpoint,
        requestOptions,
        apiVersion: (0, pre_fetch_processing_1.getApiVersion)(request),
    }).catch(e => {
        throw new errors_1.GoogleGenerativeAIError('exception posting request to model', e);
    });
    await (0, post_fetch_processing_1.throwErrorIfNotOK)(response).catch(e => {
        throw e;
    });
    return (0, post_fetch_processing_1.processUnary)(response);
}
exports.generateContent = generateContent;
/**
 * Make an async stream request to generate content. The response will be
 * returned in stream.
 * @param {GenerateContentRequest} request - {@link GenerateContentRequest}
 * @returns {Promise<StreamGenerateContentResult>} Promise of {@link
 *     StreamGenerateContentResult}
 */
async function generateContentStream(location, resourcePath, token, request, apiEndpoint, generationConfig, safetySettings, tools, toolConfig, requestOptions) {
    var _a, _b, _c, _d;
    request = (0, pre_fetch_processing_1.formatContentRequest)(request, generationConfig, safetySettings);
    (0, pre_fetch_processing_1.validateGenerateContentRequest)(request);
    if (request.generationConfig) {
        request.generationConfig = (0, pre_fetch_processing_1.validateGenerationConfig)(request.generationConfig);
    }
    const generateContentRequest = {
        contents: request.contents,
        systemInstruction: request.systemInstruction,
        cachedContent: request.cachedContent,
        generationConfig: (_a = request.generationConfig) !== null && _a !== void 0 ? _a : generationConfig,
        safetySettings: (_b = request.safetySettings) !== null && _b !== void 0 ? _b : safetySettings,
        tools: (_c = request.tools) !== null && _c !== void 0 ? _c : tools,
        toolConfig: (_d = request.toolConfig) !== null && _d !== void 0 ? _d : toolConfig,
    };
    const response = await (0, post_request_1.postRequest)({
        region: location,
        resourcePath,
        resourceMethod: constants.STREAMING_GENERATE_CONTENT_METHOD,
        token: await token,
        data: generateContentRequest,
        apiEndpoint,
        requestOptions,
        apiVersion: (0, pre_fetch_processing_1.getApiVersion)(request),
    }).catch(e => {
        throw new errors_1.GoogleGenerativeAIError('exception posting request', e);
    });
    await (0, post_fetch_processing_1.throwErrorIfNotOK)(response).catch(e => {
        throw e;
    });
    return (0, post_fetch_processing_1.processStream)(response);
}
exports.generateContentStream = generateContentStream;
//# sourceMappingURL=generate_content.js.map