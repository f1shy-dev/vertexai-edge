"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleAuth = void 0;
const jose_1 = require("jose");
class GoogleAuth {
    constructor(options) {
        this.options = options;
    }
    async getAccessToken() {
        var _a, _b, _c, _d, _e;
        const clientEmail = ((_b = (_a = this.options) === null || _a === void 0 ? void 0 : _a.credentials) === null || _b === void 0 ? void 0 : _b.client_email) ||
            process.env.GOOGLE_SA_CLIENT_EMAIL;
        const privKey = ((_d = (_c = this.options) === null || _c === void 0 ? void 0 : _c.credentials) === null || _d === void 0 ? void 0 : _d.private_key) ||
            process.env.GOOGLE_SA_PRIVATE_KEY;
        if (!clientEmail) {
            throw new Error('Missing client email');
        }
        if (!privKey) {
            throw new Error('Missing private key');
        }
        const payload = {
            iss: clientEmail,
            scope: ((_e = this.options) === null || _e === void 0 ? void 0 : _e.scopes) || '',
            aud: 'https://www.googleapis.com/oauth2/v4/token',
            exp: Math.floor(Date.now() / 1000) + 60 * 60,
            iat: Math.floor(Date.now() / 1000),
        };
        const rawPrivateKey = privKey.replace(/\\n/g, '\n');
        try {
            const privateKey = await (0, jose_1.importPKCS8)(rawPrivateKey, 'RS256');
            const jwt = await new jose_1.SignJWT(payload)
                .setProtectedHeader({ alg: 'RS256' })
                .setIssuedAt()
                .setIssuer(clientEmail)
                .setAudience('https://www.googleapis.com/oauth2/v4/token')
                .setExpirationTime('1h')
                .sign(privateKey);
            const tokenResponse = await fetch('https://www.googleapis.com/oauth2/v4/token', {
                method: 'POST',
                body: JSON.stringify({
                    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    assertion: jwt,
                }),
                headers: { 'Content-Type': 'application/json' },
            });
            const token = (await tokenResponse.json());
            return token.access_token;
        }
        catch (error) {
            console.error(error);
            throw error;
        }
    }
}
exports.GoogleAuth = GoogleAuth;
//# sourceMappingURL=index.js.map