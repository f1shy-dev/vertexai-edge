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
const index_1 = require("../src/index");
describe('SDK', () => {
    it('should import VertexAI', () => {
        const PROJECT = 'test_project';
        const LOCATION = 'test_location';
        const vertexai = new index_1.VertexAI({
            project: PROJECT,
            location: LOCATION,
        });
        expect(vertexai).toBeInstanceOf(index_1.VertexAI);
    });
});
//# sourceMappingURL=index_test.js.map