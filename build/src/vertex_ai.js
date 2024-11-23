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
exports.VertexAI = void 0;
/* tslint:disable */
const index_1 = require("../gauth-library-edge/index");
const models_1 = require("./models");
const errors_1 = require("./types/errors");
const Resources = require("./resources");
const cached_contents_1 = require("./resources/cached_contents");
/**
 * The `VertexAI` class is the base class for authenticating to Vertex AI.
 * To use Vertex AI's generative AI models, use the `getGenerativeModel` method.
 * To use generative AI features that are in Preview, use the `preview`
 * namespace.
 */
class VertexAI {
    /**
     * @constructor
     * @param init - assign authentication related information,
     *     including the project and location strings, to instantiate a Vertex AI
     * client.
     * @throws {IllegalArgumentError}
  
     */
    constructor(init) {
        const opts = validateGoogleAuthOptions(init.project, init.googleAuthOptions);
        this.location = resolveLocation(init.location);
        this.project = resolveProject(init.project);
        this.googleAuth = new index_1.GoogleAuth(opts);
        this.apiEndpoint = init.apiEndpoint;
        this.preview = new VertexAIPreview(this.project, this.location, this.googleAuth, this.apiEndpoint);
    }
    /**
     * Gets the GenerativeModel class instance.
     *
     * This method creates a new instance of the `GenerativeModel` class with the
     * platform initialization parameters provided in {@link VertexInit} and model
     * initialization parameters provided in {@link ModelParams}. You can
     * optionally provide {@link RequestOptions} to override the default request
     * options.
     *
     * @example
     * ```
     * const project = 'your-cloud-project';
     * const location = 'us-central1';
     * const textModel =  'gemini-1.0-pro';
     * const visionModel = 'gemini-1.0-pro-vision';
     *
     * const vertexAI = new VertexAI({project: project, location: location});
     *
     * // Instantiate models
     * const generativeModel = vertexAI.getGenerativeModel({
     *   model: textModel,
     *   // The following parameters are optional
     *   // They can also be passed to individual content generation requests
     *   safetySettings: [{
     *                      category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
     *                      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE
     *                     }],
     *   generationConfig: {maxOutputTokens: 256},
     * });
     *
     * const generativeVisionModel = vertexAI.getGenerativeModel({
     *   model: visionModel,
     * });
     *
     * const generativeModelPreview = vertexAI.preview.getGenerativeModel({
     *   model: textModel,
     * });
     * ```
     *
     * @param modelParams - {@link ModelParams} Parameters to
     *     specify the generative model.
     * @param requestOptions - {@link RequestOptions} Parameters to specify
     *     request options
     * @returns Instance of the GenerativeModel class.
     */
    getGenerativeModel(modelParams, requestOptions) {
        const getGenerativeModelParams = {
            model: modelParams.model,
            project: this.project,
            location: this.location,
            googleAuth: this.googleAuth,
            apiEndpoint: this.apiEndpoint,
            safetySettings: modelParams.safetySettings,
            generationConfig: modelParams.generationConfig,
            tools: modelParams.tools,
            toolConfig: modelParams.toolConfig,
            requestOptions: requestOptions,
            systemInstruction: modelParams.systemInstruction,
        };
        return new models_1.GenerativeModel(getGenerativeModelParams);
    }
    getProject() {
        return this.project;
    }
    getLocation() {
        return this.location;
    }
}
exports.VertexAI = VertexAI;
/**
 * The preview namespace for VertexAI. Users invoke the `getGenerativeModel`
 * method to start using generative AI features that are in preview.
 */
class VertexAIPreview {
    /**
     * @constructor
     * @param project - The Google Cloud project to use for the request
     * @param location - location The Google Cloud project location to use for the
     *     request
     * @param googleAuth - The GoogleAuthen class instance from
     *     ../../gauth-library-edge/index.
     *        Complete list of authentication options is documented in the
     * GoogleAuthOptions interface:
     *        https://github.com/googleapis/../../gauth-library-edge/index-nodejs/blob/main/src/auth/googleauth.ts
     * @param apiEndpoint - [apiEndpoint] The base Vertex AI endpoint to use for
     *     the request. If
     *        not provided, the default regionalized endpoint
     *        (i.e. us-central1-aiplatform.googleapis.com) will be used.
     */
    constructor(project, location, googleAuth, apiEndpoint) {
        this.project = project;
        this.location = location;
        this.googleAuth = googleAuth;
        this.apiEndpoint = apiEndpoint;
        this.apiClient = new Resources.ApiClient(this.project, this.location, 'v1beta1', this.googleAuth);
        this.cachedContents = new Resources.CachedContents(this.apiClient);
    }
    /**
     * @param modelParams - {@link ModelParams} Parameters to
     *     specify the generative model.
     * @returns Instance of the GenerativeModelPreview class.
     */
    getGenerativeModel(modelParams, requestOptions) {
        const getGenerativeModelParams = {
            model: modelParams.model,
            project: this.project,
            location: this.location,
            googleAuth: this.googleAuth,
            apiEndpoint: this.apiEndpoint,
            safetySettings: modelParams.safetySettings,
            generationConfig: modelParams.generationConfig,
            tools: modelParams.tools,
            toolConfig: modelParams.toolConfig,
            requestOptions: requestOptions,
            systemInstruction: modelParams.systemInstruction,
        };
        return new models_1.GenerativeModelPreview(getGenerativeModelParams);
    }
    getGenerativeModelFromCachedContent(cachedContent, modelParams, requestOptions) {
        if (!cachedContent.name) {
            throw new errors_1.ClientError('Cached content must contain a `name` field.');
        }
        if (!cachedContent.model) {
            throw new errors_1.ClientError('Cached content must contain a `model` field.');
        }
        validateCachedContentModel(cachedContent.model);
        /**
         * Not checking tools and toolConfig for now as it would require a deep
         * equality comparison and isn't likely to be a common case.
         */
        const disallowedDuplicates = ['model', 'systemInstruction'];
        for (const key of disallowedDuplicates) {
            if ((modelParams === null || modelParams === void 0 ? void 0 : modelParams[key]) &&
                cachedContent[key] &&
                (modelParams === null || modelParams === void 0 ? void 0 : modelParams[key]) !== cachedContent[key]) {
                if (key === 'model') {
                    const modelParamsComp = parseModelName(modelParams[key]);
                    const cachedContentComp = parseModelName(cachedContent[key]);
                    if (modelParamsComp === cachedContentComp) {
                        continue;
                    }
                }
                throw new errors_1.ClientError(`Different value for "${key}" specified in modelParams` +
                    ` (${modelParams[key]}) and cachedContent (${cachedContent[key]})`);
            }
        }
        cachedContent.name = (0, cached_contents_1.inferFullResourceName)(this.project, this.location, cachedContent.name);
        const modelParamsFromCache = {
            model: cachedContent.model,
            project: this.project,
            location: this.location,
            googleAuth: this.googleAuth,
            apiEndpoint: this.apiEndpoint,
            safetySettings: modelParams === null || modelParams === void 0 ? void 0 : modelParams.safetySettings,
            generationConfig: modelParams === null || modelParams === void 0 ? void 0 : modelParams.generationConfig,
            tools: cachedContent.tools,
            toolConfig: cachedContent.toolConfig,
            requestOptions: requestOptions,
            systemInstruction: cachedContent.systemInstruction,
            cachedContent,
        };
        return new models_1.GenerativeModelPreview(modelParamsFromCache);
    }
}
function validateCachedContentModel(modelName) {
    if (modelName.startsWith('models/') ||
        (modelName.startsWith('projects/') &&
            modelName.includes('/publishers/google/models/')) ||
        !modelName.includes('/')) {
        return;
    }
    throw new errors_1.ClientError(`Cached content model name must start with "models/" or match "projects/.*/publishers/google/models/.*" or is a model name listed at https://cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions. Received: ${modelName}`);
}
function parseModelName(modelName) {
    if (!modelName.includes('/')) {
        return modelName;
    }
    return modelName.split('/').pop();
}
function validateGoogleAuthOptions(project, googleAuthOptions) {
    let opts;
    const requiredScope = 'https://www.googleapis.com/auth/cloud-platform';
    if (!googleAuthOptions) {
        opts = {
            scopes: requiredScope,
        };
        return opts;
    }
    if (googleAuthOptions.projectId && googleAuthOptions.projectId !== project) {
        throw new Error(`inconsistent project ID values. argument project got value ${project} but googleAuthOptions.projectId got value ${googleAuthOptions.projectId}`);
    }
    opts = googleAuthOptions;
    if (!opts.scopes) {
        opts.scopes = requiredScope;
        return opts;
    }
    if ((typeof opts.scopes === 'string' && opts.scopes !== requiredScope) ||
        (Array.isArray(opts.scopes) && opts.scopes.indexOf(requiredScope) < 0)) {
        throw new errors_1.GoogleAuthError(`input GoogleAuthOptions.scopes ${opts.scopes} doesn't contain required scope ${requiredScope}, please include ${requiredScope} into GoogleAuthOptions.scopes or leave GoogleAuthOptions.scopes undefined`);
    }
    return opts;
}
function resolveProject(projectFromInput) {
    const projectNotFoundErrorMessage = 'Unable to infer your project.' +
        'Please provide a project Id by one of the following:' +
        '\n- Passing a constructor argument by using new VertexAI({project: my-project})' +
        '\n- Setting project using `gcloud config set project my-project`';
    if (projectFromInput) {
        return projectFromInput;
    }
    const inferredProjectFromEnv = process.env.GOOGLE_CLOUD_PROJECT;
    if (inferredProjectFromEnv) {
        return inferredProjectFromEnv;
    }
    throw new errors_1.IllegalArgumentError(projectNotFoundErrorMessage);
}
function resolveLocation(locationFromInput) {
    if (locationFromInput) {
        return locationFromInput;
    }
    const inferredLocation = process.env.GOOGLE_CLOUD_REGION || process.env.CLOUD_ML_REGION;
    if (inferredLocation) {
        return inferredLocation;
    }
    return 'us-central1';
}
//# sourceMappingURL=vertex_ai.js.map