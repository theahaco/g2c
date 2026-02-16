/** 65-byte SEC1 uncompressed P-256 public key and credential ID from WebAuthn registration. */
export interface PasskeyRegistration {
  /** 65-byte uncompressed P-256 public key (0x04 || x || y). */
  publicKey: Uint8Array;
  /** Raw credential ID from the authenticator. */
  credentialId: Uint8Array;
}

/** Parsed WebAuthn assertion components ready for Soroban auth injection. */
export interface PasskeySignature {
  /** Raw authenticator data bytes. */
  authenticatorData: Uint8Array;
  /** Raw client data JSON bytes. */
  clientDataJson: Uint8Array;
  /** 64-byte compact ECDSA signature (r || s), low-S normalized. */
  signature: Uint8Array;
}

/** Network and contract configuration. */
export interface NetworkConfig {
  /** Soroban RPC URL. */
  rpcUrl: string;
  /** Stellar network passphrase (e.g. "Test SDF Network ; September 2015"). */
  networkPassphrase: string;
  /** Contract ID of the deployed factory contract. */
  factoryContractId: string;
}
