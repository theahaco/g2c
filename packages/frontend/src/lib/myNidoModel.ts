export type MyNidoRow = {
  contractId: string;
  name: string | null;
  status: "active" | "pending";
  /** present only for pending rows → resume at /new-account/#salt=<resumeKey> */
  resumeKey?: string;
};

export type MyNidoModel = {
  state: "empty" | "single" | "multi";
  rows: MyNidoRow[];
};

export type PendingAccount = { contractId: string; secretKey?: string; setupKey?: string };

/**
 * Derive the My Nido menu model from localStorage-backed account state.
 * Pure: no DOM, no network. `state` is `"empty"` when there are no active
 * accounts (pending rows may still appear); `"single"` when there is exactly
 * one active account and no pending rows; `"multi"` when there are two or more
 * active accounts, or one active plus pending. Pending accounts are appended as
 * rows after the active ones.
 */
export function buildMyNidoModel(
  accounts: string[],
  pending: PendingAccount[],
  nameOf: (id: string) => string | null,
): MyNidoModel {
  const activeRows: MyNidoRow[] = accounts.map((contractId) => ({
    contractId,
    name: nameOf(contractId),
    status: "active",
  }));

  const activeSet = new Set(accounts);
  const pendingRows: MyNidoRow[] = pending
    .filter((p) => !activeSet.has(p.contractId))
    .map((p) => ({
      contractId: p.contractId,
      name: nameOf(p.contractId),
      status: "pending",
      resumeKey: p.setupKey ?? p.secretKey,
    }));

  const activeCount = accounts.length;
  const hasPending = pendingRows.length > 0;
  const state: MyNidoModel["state"] =
    activeCount === 0
      ? "empty"
      : activeCount === 1 && !hasPending
        ? "single"
        : "multi";

  return { state, rows: [...activeRows, ...pendingRows] };
}
