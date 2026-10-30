import { api, type Passkey } from "./api";

/* eslint-disable @typescript-eslint/no-explicit-any */

const toBuffer = (value: string): ArrayBuffer =>
  Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;

const toText = (value: ArrayBuffer): string =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export const passkeysSupported = () => window.isSecureContext && "PublicKeyCredential" in window;

/** Browsers refuse WebAuthn on an IP address, whatever the protocol. */
export const passkeysHereReason = () =>
  !passkeysSupported() || /^[\d.]+$|:/.test(window.location.hostname)
    ? "Passkeys работают только по домену и HTTPS. Откройте админку по доменному имени: включить HTTPS можно в карточке выше."
    : "";

/** What to tell the user; closing the browser's window is not a failure worth a red message. */
export function passkeyError(err: unknown): string {
  const name = (err as Error).name;
  if (name === "NotAllowedError" || name === "AbortError") return "Отменено или время ожидания вышло";
  if (name === "InvalidStateError") return "Этот ключ уже добавлен";
  if (name === "SecurityError") return "Браузер не разрешает Passkeys на этом адресе";
  return (err as Error).message;
}

export async function addPasskey(name: string): Promise<Passkey> {
  const { challenge_id, options } = await api.passkeyOptions();
  const made = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: toBuffer(options.challenge),
      user: { ...options.user, id: toBuffer(options.user.id) },
      excludeCredentials: (options.excludeCredentials ?? []).map((c: any) => ({ ...c, id: toBuffer(c.id) })),
    } as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential;
  const response = made.response as AuthenticatorAttestationResponse;
  return api.addPasskey(challenge_id, name, {
    id: made.id,
    rawId: toText(made.rawId),
    type: made.type,
    response: {
      clientDataJSON: toText(response.clientDataJSON),
      attestationObject: toText(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  });
}

export async function signInWithPasskey(): Promise<{ username: string }> {
  const { challenge_id, options } = await api.passkeyLoginOptions();
  const got = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: toBuffer(options.challenge),
      allowCredentials: (options.allowCredentials ?? []).map((c: any) => ({ ...c, id: toBuffer(c.id) })),
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential;
  const response = got.response as AuthenticatorAssertionResponse;
  return api.passkeyLogin(challenge_id, {
    id: got.id,
    rawId: toText(got.rawId),
    type: got.type,
    response: {
      clientDataJSON: toText(response.clientDataJSON),
      authenticatorData: toText(response.authenticatorData),
      signature: toText(response.signature),
      userHandle: response.userHandle ? toText(response.userHandle) : undefined,
    },
  });
}
