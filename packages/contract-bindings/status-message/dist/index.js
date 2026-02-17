import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";
if (typeof window !== "undefined") {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const networks = {
    testnet: {
        networkPassphrase: "Test SDF Network ; September 2015",
        contractId: "CD5FK6CQ7QIZ5ONARG36Y53ERI5PIBGELSJUTD7OXYLK6EQAS4N3TFBV",
    },
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy(null, options);
    }
    constructor(options) {
        super(new ContractSpec([
            "AAAAAAAAAAAAAAAOdWRwYXRlX21lc3NhZ2UAAAAAAAIAAAAAAAAAB21lc3NhZ2UAAAAAEAAAAAAAAAAGYXV0aG9yAAAAAAATAAAAAA==",
            "AAAAAAAAAAAAAAALZ2V0X21lc3NhZ2UAAAAAAQAAAAAAAAAGYXV0aG9yAAAAAAATAAAAAQAAA+gAAAAQ",
        ]), options);
        this.options = options;
    }
    fromJSON = {
        udpate_message: (this.txFromJSON),
        get_message: (this.txFromJSON),
    };
}
