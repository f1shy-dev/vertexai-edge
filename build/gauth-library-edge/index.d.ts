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
export declare class GoogleAuth {
    private options?;
    constructor(options?: GoogleAuthOptions);
    getAccessToken(): Promise<string | null | undefined>;
}
