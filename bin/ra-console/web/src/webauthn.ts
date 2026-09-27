// Cérémonie d'authentification WebAuthn côté navigateur : seule l'API
// standard `navigator.credentials` est utilisée (docs/UI-UX.md §7). Les
// options viennent du serveur (webauthn-rs, JSON niveau 3) ; l'assertion est
// rendue dans la même forme, que le serveur vérifie seul.

import { fromBase64Url, toBase64Url } from "./b64url";

interface RequestOptionsJson {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: { type: "public-key"; id: string; transports?: AuthenticatorTransport[] }[];
  userVerification?: UserVerificationRequirement;
}

export async function assert(options: RequestOptionsJson): Promise<unknown> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: fromBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((c) => ({
      type: c.type,
      id: fromBase64Url(c.id),
      ...(c.transports ? { transports: c.transports } : {}),
    })),
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
    ...(options.rpId !== undefined ? { rpId: options.rpId } : {}),
    ...(options.userVerification !== undefined ? { userVerification: options.userVerification } : {}),
  };
  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (credential === null) throw new Error("aucune clé n'a répondu");
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
    },
    extensions: {},
  };
}
