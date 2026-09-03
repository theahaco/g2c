const key = (contractId: string) => `nido:${contractId}:ephemeralG`;

export function saveEphemeralGAddress(contractId: string, gAddress: string): void {
  localStorage.setItem(key(contractId), gAddress);
}

export function loadEphemeralGAddress(contractId: string): string | null {
  return localStorage.getItem(key(contractId));
}

export function clearEphemeralGAddress(contractId: string): void {
  localStorage.removeItem(key(contractId));
}