import { Actor, HttpAgent } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { IDL } from "@dfinity/candid";

// Mainnet: host público IC + canister `access` de producción.
// (El modo réplica local vive en git history; este build es mainnet.)
export const REPLICA_HOST = "https://icp0.io";
// Canister `access` en mainnet (desplegado con nebulock-prod, Task 5→mainnet).
export const ACCESS_CANISTER_ID = "qykla-5iaaa-aaaah-av4ua-cai";
// Internet Identity de producción.
export const II_URL = "https://identity.ic0.app";

// IDL del canister access: allowlist + credencial nb2 + F2 (entitlements,
// pago ICRC-1, provisioning). Sincronizada con app/canisters/access/access.did
// (el test export_did_file la regenera; si el .did cambia, actualizar aquí).
const accessIdlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const Entitlement = IDL.Record({
    active: IDL.Bool,
    tier: IDL.Nat8,
    paid_ns: IDL.Nat64,
    expires_ns: IDL.Nat64,
  });
  const ProvisionStatus = IDL.Variant({
    None: IDL.Null,
    Active: IDL.Null,
    Pending: IDL.Null,
  });
  const ProvisionState = IDL.Record({
    url: IDL.Opt(IDL.Text),
    status: ProvisionStatus,
    attestation_ref: IDL.Opt(IDL.Text),
    tier: IDL.Nat8,
    activated_ns: IDL.Nat64,
    requested_ns: IDL.Nat64,
  });
  return IDL.Service({
    me: IDL.Func([], [IDL.Principal], ["query"]),
    is_allowed_caller: IDL.Func([], [IDL.Bool], ["query"]),
    issue_credential: IDL.Func([], [IDL.Text], []),
    get_my_entitlement: IDL.Func([], [Entitlement], ["query"]),
    is_entitled_caller: IDL.Func([], [IDL.Bool], ["query"]),
    get_payment_info: IDL.Func([IDL.Nat8], [IDL.Nat64, IDL.Vec(IDL.Nat8)], ["query"]),
    request_provision: IDL.Func([IDL.Nat8], [ProvisionState], []),
    get_my_container: IDL.Func([], [ProvisionState], ["query"]),
    get_attestation_ttl_ns: IDL.Func([], [IDL.Nat64], ["query"]),
  });
};

export type F2Entitlement = {
  active: boolean;
  tier: number;
  paid_ns: bigint;
  expires_ns: bigint;
};

export type F2ProvisionState = {
  url: [] | [string];
  status: { None?: null; Active?: null; Pending?: null };
  attestation_ref: [] | [string];
  tier: number;
  activated_ns: bigint;
  requested_ns: bigint;
};

export type AccessActor = {
  me: () => Promise<import("@dfinity/principal").Principal>;
  is_allowed_caller: () => Promise<boolean>;
  issue_credential: () => Promise<string>;
  get_my_entitlement: () => Promise<F2Entitlement>;
  is_entitled_caller: () => Promise<boolean>;
  get_payment_info: (tier: number) => Promise<[bigint, number[]]>;
  request_provision: (tier: number) => Promise<F2ProvisionState>;
  get_my_container: () => Promise<F2ProvisionState>;
  get_attestation_ttl_ns: () => Promise<bigint>;
};

let authClient: AuthClient | null = null;

export async function getAuthClient(): Promise<AuthClient> {
  if (!authClient) {
    authClient = await AuthClient.create();
  }
  return authClient;
}

export async function makeAccessActor(
  identity: import("@dfinity/agent").Identity,
): Promise<AccessActor> {
  const agent = new HttpAgent({ host: REPLICA_HOST, identity });
  // Mainnet: NO llamar a fetchRootKey(). La root key hardcodeada del
  // agente es la que vale; ir a buscarla la dejaría en manos de un MITM.
  return Actor.createActor<AccessActor>(accessIdlFactory, {
    agent,
    canisterId: ACCESS_CANISTER_ID,
  });
}
