// Interop helper del canal cifrado: espejo EXACTO de sealMessage/openMessage
// de app/frontend/src/attest/session.ts (WebCrypto AES-GCM), para que el test
// de Python (`test_channel.py`) verifique cifrado/descifrado byte a byte entre
// Python y un cliente WebCrypto real.
//
// Entrada (argv[2], JSON): { op, keyHex?, masterHex?, info?, seq?, plaintext?, sealed? }
//   op "seal"|"open":   AES-GCM con keyHex (subclave direccional ya derivada)
//   op "expand":         HKDF-SHA256(masterHex, salt="", info) -> 32B (espejo de
//                        deriveDirectionalKey en session.ts y derive_directional_keys
//                        en attest_server.py; run-5 B-01)
// Salida (stdout, JSON):  { sealed? }  o  { plaintext? }  o  { keyHex? }

import { webcrypto } from "node:crypto";

const crypto = webcrypto;

async function aesKey(keyHex) {
  const raw = Uint8Array.from(Buffer.from(keyHex, "hex"));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function ivFor(seq) {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(0, seq, false); // big-endian, resto a cero
  return iv;
}

async function seal(keyHex, seq, plaintext) {
  const key = await aesKey(keyHex);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivFor(seq) },
    key,
    new TextEncoder().encode(plaintext),
  );
  return Buffer.from(new Uint8Array(ct)).toString("base64");
}

async function open(keyHex, seq, sealed) {
  const key = await aesKey(keyHex);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivFor(seq) },
    key,
    Uint8Array.from(Buffer.from(sealed, "base64")),
  );
  return new TextDecoder().decode(pt);
}

async function expand(masterHex, info) {
  const master = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(Buffer.from(masterHex, "hex")),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const sub = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    master,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", sub));
  return Buffer.from(raw).toString("hex");
}

async function main() {
  const inp = JSON.parse(process.argv[2]);
  if (inp.op === "seal") {
    console.log(JSON.stringify({ sealed: await seal(inp.keyHex, inp.seq, inp.plaintext) }));
  } else if (inp.op === "open") {
    console.log(JSON.stringify({ plaintext: await open(inp.keyHex, inp.seq, inp.sealed) }));
  } else if (inp.op === "expand") {
    console.log(JSON.stringify({ keyHex: await expand(inp.masterHex, inp.info) }));
  } else {
    throw new Error("op desconocida: " + inp.op);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
