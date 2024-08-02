import {SignJWT, importPKCS8} from 'jose';

export interface CredentialBody {
  client_email?: string;
  private_key?: string;
  universe_domain?: string;
}

export interface GoogleAuthOptions {
  credentials?: CredentialBody;
  /**
   * Required scopes for the desired API request
   */
  scopes?: string | string[];
  /**
   * Your project ID.
   */
  projectId?: string;
  /**
   * The default service domain for a given Cloud universe.
   *
   * This is an ergonomic equivalent to {@link clientOptions}'s `universeDomain`
   * property and will be set for all generated {@link AuthClient}s.
   */
  universeDomain?: string;
}

export class GoogleAuth {
  private options?: GoogleAuthOptions;

  constructor(options?: GoogleAuthOptions) {
    this.options = options;
  }

  async getAccessToken() {
    const clientEmail =
      this.options?.credentials?.client_email ||
      process.env.GOOGLE_SA_CLIENT_EMAIL;

    const privKey =
      this.options?.credentials?.private_key ||
      process.env.GOOGLE_SA_PRIVATE_KEY;

    if (!clientEmail) {
      throw new Error('Missing client email');
    }

    if (!privKey) {
      throw new Error('Missing private key');
    }

    const payload = {
      iss: clientEmail,
      scope: this.options?.scopes || '',
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
      iat: Math.floor(Date.now() / 1000),
    };

    const rawPrivateKey = privKey.replace(/\\n/g, '\n');

    try {
      const privateKey = await importPKCS8(rawPrivateKey, 'RS256');

      const jwt = await new SignJWT(payload)
        .setProtectedHeader({alg: 'RS256'})
        .setIssuedAt()
        .setIssuer(clientEmail)
        .setAudience('https://www.googleapis.com/oauth2/v4/token')
        .setExpirationTime('1h')
        .sign(privateKey);

      const tokenResponse = await fetch(
        'https://www.googleapis.com/oauth2/v4/token',
        {
          method: 'POST',
          body: JSON.stringify({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: jwt,
          }),
          headers: {'Content-Type': 'application/json'},
        }
      );

      const token = (await tokenResponse.json()) as {
        access_token: string;
        expires_in: number;
        token_type: string;
      };

      return token.access_token as string | null | undefined;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }
}
