/**
 * In-page signing of target-contract calls with a delegated Nido session
 * passkey — no per-transaction redirect to the wallet.
 *
 * This is the payoff of "log in with Nido = create a passkey for this dApp"
 * (see `delegationHandover.ts`): once a session key is delegated, the dApp
 * signs the target contract's calls locally with that passkey (Touch ID /
 * device unlock at the dApp origin) and submits.
 *
 * Two flows share one signing core (`signSessionCallInPage`), and BOTH submit
 * gaslessly through the Nido relayer: the signed `{func, auth}` pair ships to
 * the relayer, whose channel accounts source + fee-bump the transaction. No fee
 * payer, no friendbot anywhere in either path.
 *
 *  - `signUpdateMessageInPage` — the status-message write. The smart account
 *    (C-address) is only the auth *author*; recording simulation borrows the
 *    relayer's public fund address as a throwaway source.
 *
 *  - `tipAuthorInPage` — a native-XLM tip via a direct
 *    `SAC.transfer(smartAccount → author, amount)`. The session key is scoped
 *    to the XLM Stellar Asset Contract with a wallet-installed spending limit.
 */

import {
	buildAuthHash,
	computeAuthDigest,
	getAuthEntry,
	injectPasskeySignature,
	hex2buf,
	loadSessionKeyMaterial,
	forgetSessionKeyMaterial,
	signWithSessionPasskey,
	extractFuncAndAuth,
	submitSorobanTransaction,
	submitXdrTransaction,
	waitForConfirmation,
} from "@nidohq/passkey-sdk"
import {
	Address,
	Asset,
	Operation,
	TransactionBuilder,
	type Transaction,
	nativeToScVal,
	rpc,
} from "@stellar/stellar-sdk"
import { Client } from "status_message"
import { rpcUrl, networkPassphrase, relayerUrl, stellarNetwork } from "../contracts/util"
import { withPasskeySheet } from "./passkeySheet"
import { decodeContractCall, buildApprovalDetails } from "./describeAuthEntry"
import { findRuleForPubkey, fetchVerifierAddress } from "./policyChainFetch"

/** Native-XLM Stellar Asset Contract id for the configured network — the
 *  target contract a tipping session key is scoped to. */
export const XLM_SAC_ID = Asset.native().contractId(networkPassphrase)

/**
 * Recording-mode simulation needs SOME existing on-chain source account; the
 * source neither signs nor pays in either gasless path (the relayer's channel
 * accounts become the real source later). The Nido relayer's fund address is
 * public and always funded on testnet, so it serves as a constant sim source
 * — no friendbot, no locally stored keypair required.
 */
const RELAYER_SIM_SOURCE = "GAL42RUBXKQSVSJWBXFTBB4GFKMPQXA3SOJVGP6UMRJT2SGEIR63JFK2"

/** True when a session passkey is already delegated for (account, contract). */
export function hasSessionKey(account: string, contractId: string): boolean {
	return loadSessionKeyMaterial(account, contractId) !== null
}

/** Param names for a contract function (from its spec) — labels the sheet's args. */
function specParamNames(client: Client, fnName: string): string[] {
	try {
		const f = client.spec.funcs().find((x) => x.name().toString() === fnName)
		return f ? f.inputs().map((i) => i.name().toString()) : []
	} catch {
		return []
	}
}

export type SignProgress = (message: string) => void

/**
 * The structural minimum the signing core needs from a built transaction:
 * whatever `injectPasskeySignature` accepts. Generic so the bindings' bundled
 * stellar-sdk `Transaction` (update_message) and this app's own (tip) both
 * round-trip through the core with their exact type preserved.
 */
type InjectableTx = Parameters<typeof injectPasskeySignature>[0]

/** What `buildTx` hands the signing core. */
export interface BuiltSessionCall<T extends InjectableTx> {
	/** Built tx whose invoke op carries the simulated (unsigned) auth entries. */
	tx: T
	/** The recording-mode simulation that produced those auth entries. */
	sim: rpc.Api.SimulateTransactionSuccessResponse
	/** Spec-derived parameter names for the approval sheet, by function name. */
	paramNames?: (fn: string) => string[]
}

/**
 * Shared session-signing core: load the (account, targetContract) session-key
 * material, let the caller build + recording-simulate the call, discover the
 * on-chain context rule for the key, compute the OZ v0.7 auth digest, run the
 * passkey ceremony inside the Nido-styled sheet, and inject the signature into
 * the built tx's auth entry. Submission is the CALLER's concern — both flows
 * ship `{func, auth}` to the relayer.
 */
export async function signSessionCallInPage<T extends InjectableTx>(opts: {
	account: string
	/** Contract the session key is scoped to (the material's storage key). */
	targetContract: string
	/** Build + recording-simulate the call. Runs AFTER the material check. */
	buildTx: () => Promise<BuiltSessionCall<T>>
	/** Heading for the approval sheet, e.g. "Approve status update". */
	approvalTitle: string
	/** Sub text for the approval sheet. */
	approvalSub?: string
	/** Flow-specific error copy (defaults match the update_message flow). */
	errors?: { noMaterial?: string; ruleMissing?: string }
	/** Ledgers the signature stays valid (sdk default 10000 ≈ 14h). Callers
	 *  that SHIP the signed entry to the relayer must set this tight (~120):
	 *  whoever holds the body can submit at any moment until expiry. Applied
	 *  identically to digest and injection — the two must never diverge. */
	expirationOffset?: number
	onProgress?: SignProgress
}): Promise<{ tx: T }> {
	const { account, targetContract, onProgress } = opts
	const note = (m: string) => onProgress?.(m)

	const material = loadSessionKeyMaterial(account, targetContract)
	if (!material) {
		throw new Error(
			opts.errors?.noMaterial ??
				'No dApp passkey for this account — click "Create dApp passkey" to delegate one first.',
		)
	}

	const { tx, sim, paramNames } = await opts.buildTx()
	const authEntry = getAuthEntry(sim)
	const lastLedger = sim.latestLedger
	const authHash = buildAuthHash(authEntry, networkPassphrase, lastLedger, opts.expirationOffset)

	note("Finding session rule on chain…")
	// The wallet's add_context_rule assigned some non-zero rule id; discover it
	// so the AuthPayload + the chain-recomputed digest reference the same rule.
	const ruleId = await findRuleForPubkey(account, material.publicKey)
	if (ruleId === null) {
		forgetSessionKeyMaterial(account, targetContract)
		throw new Error(
			opts.errors?.ruleMissing ??
				"Session passkey is not installed on chain (the delegation never committed). " +
					"Create the dApp passkey again.",
		)
	}
	const contextRuleIds = [ruleId]
	const verifierAddress = await fetchVerifierAddress(account)

	note("Touch your authenticator to sign…")
	// OZ v0.7+ accounts verify sha256(signature_payload || context_rule_ids.to_xdr()).
	const authDigest = computeAuthDigest(new Uint8Array(authHash), contextRuleIds)
	// Decode what the signature actually authorises straight from the auth entry
	// (what-you-see-is-what-you-sign) rather than restating app inputs, so the
	// sheet provably reflects the signed payload. Values render via textContent,
	// so decoded user input (the message) can't inject into the dialog.
	const call = decodeContractCall(authEntry.rootInvocation())
	const details = call
		? buildApprovalDetails(call, paramNames?.(call.fn) ?? [])
		: [{ label: "Warning", value: "Could not decode this authorization." }]

	// Wrap the real in-page ceremony in the Nido-styled confirm sheet — the OS
	// passkey prompt is browser chrome we can't restyle, but this frames it.
	const parsed = await withPasskeySheet(
		() => signWithSessionPasskey(material.credentialId, new Uint8Array(authDigest)),
		{
			title: opts.approvalTitle,
			sub: opts.approvalSub ?? "Confirm with your dApp passkey.",
			details,
		},
	)

	// Inject the session-key signature into the built tx's auth entry in OZ
	// v0.7 AuthPayload shape, threading the same contextRuleIds.
	injectPasskeySignature(
		tx,
		parsed,
		verifierAddress,
		hex2buf(material.publicKey),
		lastLedger,
		opts.expirationOffset,
		contextRuleIds,
	)
	return { tx }
}

/**
 * Build, session-passkey-sign in-page, and submit an `update_message` call.
 * Throws if no session key is delegated for (account, contractId) — the caller
 * should prompt the user to "Create dApp passkey" (delegate) first.
 */
export async function signUpdateMessageInPage(opts: {
	account: string
	message: string
	contractId: string
	onProgress?: SignProgress
}): Promise<{ hash: string }> {
	const { account, message, contractId, onProgress } = opts
	const note = (m: string) => onProgress?.(m)

	const { tx: signedTx } = await signSessionCallInPage({
		account,
		targetContract: contractId,
		// Signed entry ships to the relayer — keep the validity window tight
		// (~10 min), mirroring the wallet's relayer mode.
		expirationOffset: 120,
		approvalTitle: "Approve status update",
		onProgress,
		buildTx: async () => {
			note("Building transaction…")
			// Recording simulation borrows the relayer's public fund address as the
			// source; the smart account is only the auth author. The relayer's
			// channel accounts source + fee-bump the real submission, so there is no
			// fee payer or friendbot in the path.
			const client = new Client({
				contractId,
				networkPassphrase,
				rpcUrl,
				publicKey: RELAYER_SIM_SOURCE,
			})
			const tx = await client.update_message({ message, author: account }, { simulate: true })
			return {
				// `tx.built` is the already-assembled tx (auth-entry templates baked in).
				tx: tx.built!,
				sim: tx.simulation as rpc.Api.SimulateTransactionSuccessResponse,
				paramNames: (fn) => specParamNames(client, fn),
			}
		},
	})

	note("Submitting via relayer…")
	// The relayer re-simulates server-side in enforce mode (running the smart
	// account's __check_auth + the session-key policy), sources the tx from a
	// channel account, and fee-bumps it from the fund address. We ship ONLY the
	// host function + the passkey-signed auth entry. Materialise in THIS bundle's
	// stellar-sdk first (the bindings ship their own copy); the signed auth
	// entries survive the XDR round-trip.
	const reparsed = TransactionBuilder.fromXDR(
		signedTx.toEnvelope().toXDR("base64"),
		networkPassphrase,
	) as Transaction
	const { func, auth } = extractFuncAndAuth(reparsed)
	if (auth.length > 1) {
		throw new Error(`Expected a single auth entry, got ${auth.length} — only the first is passkey-signed.`)
	}
	const submitted = await submitSorobanTransaction({ func, auth }, relayerUrl)
	if (!submitted.transactionId) {
		throw new Error("Relayer accepted the update but returned no transaction id")
	}
	const confirmed = await waitForConfirmation(submitted.transactionId, relayerUrl)
	if (!confirmed.hash) throw new Error("Relayer confirmed without a transaction hash")
	return { hash: confirmed.hash }
}

/**
 * Tip `author` some native XLM from the connected smart account, gaslessly:
 * a direct `SAC.transfer(account → author, stroops)` signed in-page with the
 * tipping session passkey and submitted through the Nido relayer. The auth
 * context is `CallContract(XLM SAC)`, so the session key's contract scope AND
 * its spending-limit policy both apply on-chain.
 *
 * No fee payer, no friendbot: recording simulation borrows the relayer's
 * public fund address as a source, and the relayer's channel accounts pay for
 * real. On rejection (over-limit, expired, out-of-scope) the relayer surfaces
 * the enforce failure — the thrown error carries its message and the session
 * material is KEPT (the rule may still allow smaller amounts later).
 */
export async function tipAuthorInPage(opts: {
	/** Connected Nido smart account (the tipper / auth author). */
	account: string
	/** Recipient address — C… or G…. */
	author: string
	/** Whole-XLM amount, e.g. 1. */
	xlm: number
	onProgress?: SignProgress
}): Promise<{ hash: string }> {
	const { account, author, xlm, onProgress } = opts
	const note = (m: string) => onProgress?.(m)
	const stroops = BigInt(Math.round(xlm * 10_000_000))

	const { tx: signedTx } = await signSessionCallInPage({
		account,
		targetContract: XLM_SAC_ID,
		// This signed entry leaves the page (shipped to the relayer) — keep the
		// validity window tight (~10 min), mirroring the wallet's relayer mode.
		expirationOffset: 120,
		approvalTitle: "Approve tip",
		errors: {
			noMaterial:
				'No tipping passkey for this account — click "Enable tipping" to delegate one first.',
			ruleMissing:
				"The tipping passkey is not installed on chain (the delegation never " +
					'committed or was revoked). Click "Enable tipping" again.',
		},
		onProgress,
		buildTx: async () => {
			note("Building transaction…")
			const server = new rpc.Server(rpcUrl, { allowHttp: stellarNetwork === "LOCAL" })
			const source = await server.getAccount(RELAYER_SIM_SOURCE)
			const op = Operation.invokeContractFunction({
				contract: XLM_SAC_ID,
				function: "transfer",
				args: [
					Address.fromString(account).toScVal(), // from = the smart account
					Address.fromString(author).toScVal(), // to = the author being tipped
					nativeToScVal(stroops, { type: "i128" }), // amount
				],
			})
			const simTx = new TransactionBuilder(source, {
				fee: "10000000",
				networkPassphrase,
			})
				.addOperation(op)
				.setTimeout(0)
				.build()
			const sim = await server.simulateTransaction(simTx)
			if (rpc.Api.isSimulationError(sim)) {
				throw new Error(`Simulation failed: ${sim.error}`)
			}
			const success = sim as rpc.Api.SimulateTransactionSuccessResponse
			// Bake the simulated footprint + (unsigned) auth-entry templates into
			// the tx so the core can inject the signature in place.
			const tx = rpc.assembleTransaction(simTx, success).build()
			// SEP-41 transfer arg names — labels the approval sheet rows.
			return { tx, sim: success, paramNames: () => ["from", "to", "amount"] }
		},
	})

	note("Submitting via relayer…")
	// The relayer re-simulates server-side in enforce mode (running the smart
	// account's __check_auth + the spending-limit policy), sources the tx from a
	// channel account, and fee-bumps it from the fund address. We ship ONLY the
	// host function + the passkey-signed auth entry.
	const { func, auth } = extractFuncAndAuth(signedTx)
	if (auth.length > 1) {
		throw new Error(`Expected a single auth entry, got ${auth.length} — only the first is passkey-signed.`)
	}
	const submitted = await submitSorobanTransaction({ func, auth }, relayerUrl)
	if (!submitted.transactionId) {
		throw new Error("Relayer accepted the tip but returned no transaction id")
	}
	const confirmed = await waitForConfirmation(submitted.transactionId, relayerUrl)
	if (!confirmed.hash) throw new Error("Relayer confirmed without a transaction hash")
	return { hash: confirmed.hash }
}
