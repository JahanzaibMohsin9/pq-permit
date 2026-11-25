import { mldsa87 } from "@qorechain/pqc";
import { parseAddress, pqSign, pqVerify } from "@qorechain/qoresign";
import { QOREX_DOWNLOAD_URLS, discoverQorexEip1193, getQorexNative, isQorexInstalled } from "@qorechain/qorex-types";
import { useEffect, useState } from "react";
import { bytesToHex, decodeFunctionData, formatUnits, getAddress, hexToBytes, hexToString, isAddress, toHex, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { CHAIN_ID, DEMO, LIVE, REPO, VIDEO, client, demoKey, erc20Abi, keyStatus, outcome, pqPermitAbi, qoreSignBytes, simulatePermit, type PermitSingle } from "./chain.ts";

type Check = { label: string; detail?: string; status: "pending" | "ok" | "bad"; value?: string };
/** The QoreX account the page is connected to, if any. */
type Wallet = { bech32: string; evm: Address; via: "native" | "evm" };
const short = (a: string) => `${a.slice(0, 8)}…${a.slice(-6)}`;
const now = () => BigInt(Math.floor(Date.now() / 1000));

function Checks({ items }: { items: Check[] }) {
  return (
    <ul className="checks">
      {items.map((c, i) => (
        <li key={i} className={c.status}>
          <span className="icon">{c.status === "ok" ? "✓" : c.status === "bad" ? "✗" : "…"}</span>
          <span>
            <b>{c.label}</b>
            {c.detail && <span className="small"> · {c.detail}</span>}
          </span>
          {c.value && <span className="val">{c.value}</span>}
        </li>
      ))}
    </ul>
  );
}

async function permitTextFor(owner: Address, p: PermitSingle): Promise<Hex> {
  return (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "permitText", args: [owner, p] })) as Hex;
}

// ------------------------------------------------------------------ 1. live proof
function LiveProof() {
  const [items, setItems] = useState<Check[]>([]);
  const [block, setBlock] = useState<bigint>();
  useEffect(() => {
    let alive = true;
    const out: Check[] = [];
    const push = (c: Check) => {
      out.push(c);
      if (alive) setItems([...out]);
    };
    (async () => {
      setBlock(await client.getBlockNumber());
      const vBal = (await client.readContract({ address: LIVE.pusd, abi: erc20Abi, functionName: "balanceOf", args: [LIVE.victim] })) as bigint;
      const vNonce = await client.getTransactionCount({ address: LIVE.victim });
      push({ label: "The hole: victim drained by a relayed ECDSA permit", detail: "standard EIP-2612 token", status: vBal === 0n && vNonce === 0 ? "ok" : "bad", value: `balance ${vBal} · txs sent ${vNonce}` });
      const ks = await keyStatus(LIVE.owner);
      push({ label: "PQ Permit owner has a registered ML-DSA-87 key", detail: "pqcKeyStatus precompile 0x…0a02", status: ks.ready ? "ok" : "bad", value: `${ks.keyBytes} B · possession ${ks.proven}` });
      const mBal = (await client.readContract({ address: LIVE.dusd, abi: erc20Abi, functionName: "balanceOf", args: [LIVE.merchant] })) as bigint;
      const [allow] = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "allowance", args: [LIVE.owner, LIVE.dusd, LIVE.relayer] })) as [bigint, number];
      push({ label: "The real ML-DSA-87 permit worked", detail: "relayed by someone else; merchant paid, rest still approved", status: mBal === 60_000_000n && allow === 40_000_000n ? "ok" : "bad", value: `merchant ${formatUnits(mBal, 6)} dUSD · left ${formatUnits(allow, 6)}` });

      // attacks, simulated now with eth_call (no gas, nothing sent)
      const nonce = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "nonces", args: [LIVE.owner] })) as bigint;
      const thief = privateKeyToAccount(generatePrivateKey());
      const p: PermitSingle = { token: LIVE.dusd, spender: thief.address, amount: 40_000_000n, expiration: Number(now() + 3600n), nonce, sigDeadline: now() + 600n };
      const message = qoreSignBytes(await permitTextFor(LIVE.owner, p));
      const ecdsa = await thief.signMessage({ message: { raw: toHex(message) } });
      const r1 = await outcome(simulatePermit(LIVE.owner, p, ecdsa));
      push({ label: "Attack: permit signed with an ECDSA key", detail: "what a leaked secp256k1 key can do", status: r1 === "InvalidSignature" ? "ok" : "bad", value: r1 });
      const fake = mldsa87.keygen(crypto.getRandomValues(new Uint8Array(32)));
      const forged = bytesToHex(mldsa87.sign(fake.secretKey, message));
      const r2 = await outcome(simulatePermit(LIVE.owner, p, forged));
      push({ label: "Attack: ML-DSA-87 signature from an attacker's key", detail: "generated in your browser just now", status: r2 === "InvalidSignature" ? "ok" : "bad", value: r2 });
      const tx = await client.getTransaction({ hash: LIVE.relayedPermitTx });
      const used = decodeFunctionData({ abi: pqPermitAbi, data: tx.input });
      const args = used.args as unknown as [Address, PermitSingle, Hex];
      const r3 = await outcome(simulatePermit(args[0], args[1], args[2]));
      push({ label: "Attack: replay the owner's real signature", detail: `${(args[2].length - 2) / 2}-byte signature read from the chain`, status: r3 !== "OK" ? "ok" : "bad", value: r3 });

      // and the positive case: a fresh permit signed now, in this browser, by the public demo owner
      const dk = demoKey();
      const dks = await keyStatus(DEMO.owner);
      const dNonce = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "nonces", args: [DEMO.owner] })) as bigint;
      const dp: PermitSingle = { ...p, nonce: dNonce };
      const dMsg = qoreSignBytes(await permitTextFor(DEMO.owner, dp));
      const dSig = pqSign(dk.secretKey, dMsg);
      const same = dks.ready && dks.pubkey.toLowerCase() === bytesToHex(dk.publicKey);
      const r4 = await outcome(simulatePermit(DEMO.owner, dp, bytesToHex(dSig)));
      push({ label: "Valid: a permit signed just now with @qorechain/qoresign", detail: "by the public demo owner, whose registered key matches its published seed", status: same && pqVerify(dk.publicKey, dMsg, dSig) && r4 === "OK" ? "ok" : "bad", value: r4 === "OK" ? "accepted" : r4 });
    })().catch((e) => push({ label: "Could not read the testnet", detail: String(e?.shortMessage ?? e?.message ?? e), status: "bad" }));
    return () => {
      alive = false;
    };
  }, []);
  return (
    <section className="card">
      <h2>1 · Live proof</h2>
      <p className="small">
        Read from qorechain-diana {block ? `at block ${block}` : "now"}, by your browser. Attacks are simulated with <code>eth_call</code>: nothing
        is sent and no gas is spent.
      </p>
      <Checks items={items} />
    </section>
  );
}

// ------------------------------------------------------------------ 2. account
/** 0x or qor1 (same 20 bytes), parsed by @qorechain/qoresign. */
function toEvm(input: string): Address | undefined {
  try {
    return getAddress(parseAddress(input.trim()).hex);
  } catch {
    return undefined;
  }
}

/** Connect QoreX (@qorechain/qorex-types): the native provider gives the qor1 account; else its EIP-6963 EVM provider. */
async function connectQorex(): Promise<Wallet> {
  const native = getQorexNative();
  if (native) {
    await native.enable(CHAIN_ID);
    const bech32 = (await native.getKey(CHAIN_ID)).bech32Address;
    return { bech32, evm: getAddress(parseAddress(bech32).hex), via: "native" };
  }
  const evm = await discoverQorexEip1193({ timeoutMs: 500 });
  if (evm) {
    const [a] = (await evm.request({ method: "eth_requestAccounts" })) as string[];
    return { bech32: parseAddress(a).bech32, evm: getAddress(a), via: "evm" };
  }
  throw new Error(isQorexInstalled() ? "QoreX did not offer an account. Unlock it and switch it to Testnet." : "QoreX not found.");
}

function Account({ owner, setOwner, wallet, setWallet }: { owner?: Address; setOwner: (a?: Address) => void; wallet?: Wallet; setWallet: (w: Wallet) => void }) {
  const [input, setInput] = useState<string>(LIVE.owner);
  const [items, setItems] = useState<Check[]>([]);
  const [err, setErr] = useState<string>();
  const [token, setToken] = useState<string>(LIVE.dusd);
  const [spender, setSpender] = useState<string>(LIVE.relayer);
  const [allowance, setAllowance] = useState<string>();

  async function connect() {
    setErr(undefined);
    try {
      const w = await connectQorex();
      setWallet(w);
      setInput(w.bech32);
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    }
  }

  useEffect(() => {
    const a = toEvm(input);
    setOwner(a);
    setItems([]);
    setAllowance(undefined);
    if (!a) return;
    let alive = true;
    (async () => {
      const ks = await keyStatus(a);
      const nonce = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "nonces", args: [a] })) as bigint;
      if (!alive) return;
      setItems([
        { label: "ML-DSA-87 key registered", status: ks.registered && ks.alg === 1 ? "ok" : "bad", value: ks.registered ? `alg ${ks.alg}, ${ks.keyBytes} B` : "no" },
        { label: "Possession proven", detail: "PQ Permit refuses keys without it", status: ks.proven ? "ok" : "bad", value: String(ks.proven) },
        { label: "Next permit nonce", status: "ok", value: nonce.toString() },
      ]);
    })().catch((e) => alive && setErr(String(e?.shortMessage ?? e)));
    return () => {
      alive = false;
    };
  }, [input, setOwner]);

  async function lookup() {
    if (!owner || !isAddress(token) || !isAddress(spender)) return setAllowance("enter a valid token and spender");
    const [amount, exp] = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "allowance", args: [owner, getAddress(token), getAddress(spender)] })) as [bigint, number];
    setAllowance(`${amount.toString()} (raw units), expires ${exp ? new Date(exp * 1000).toUTCString() : "never set"}`);
  }

  return (
    <section className="card">
      <h2>2 · Check an account</h2>
      <p className="small">
        Any owner, as 0x or qor1. The defaults are the owner from the testnet run, its token (dUSD) and its spender. To sign a valid permit
        without a wallet, pick the <b>public demo owner</b>.
      </p>
      <label>Owner</label>
      <input value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} />
      <div className="row">
        <button className="ghost" onClick={connect}>Use my QoreX account</button>
        <button className="ghost" onClick={() => setInput(parseAddress(DEMO.owner).bech32)}>Use the public demo owner</button>
      </div>
      {wallet && (
        <p className="small">
          QoreX connected ({wallet.via === "native" ? "native provider" : "EVM provider"}): {wallet.bech32}
        </p>
      )}
      {err && (
        <div className="note">
          {err}{" "}
          {err.startsWith("QoreX not found") && (
            <>
              <a href={QOREX_DOWNLOAD_URLS.chrome} target="_blank" rel="noreferrer">Get QoreX</a> and switch it to Testnet, or paste an address.
            </>
          )}
        </div>
      )}
      {owner && <Checks items={items} />}
      <div className="grid">
        <div>
          <label>Token</label>
          <input value={token} onChange={(e) => setToken(e.target.value.trim())} spellCheck={false} />
        </div>
        <div>
          <label>Spender</label>
          <input value={spender} onChange={(e) => setSpender(e.target.value.trim())} spellCheck={false} />
        </div>
      </div>
      <button className="ghost" disabled={!owner} onClick={() => lookup().catch((e) => setAllowance(String(e?.shortMessage ?? e)))}>
        Read allowance
      </button>
      {allowance && <p className="small">Allowance: {allowance}</p>}
    </section>
  );
}

// ------------------------------------------------------------------ 3. compose
/** Base64 (QoreSign MessageSignature fields are base64) to 0x hex. */
const b64ToHex = (b: string) => bytesToHex(Uint8Array.from(atob(b), (c) => c.charCodeAt(0)));

function Compose({ owner, wallet }: { owner?: Address; wallet?: Wallet }) {
  const [token, setToken] = useState<string>(LIVE.dusd);
  const [spender, setSpender] = useState<string>(LIVE.relayer);
  const [amount, setAmount] = useState("1000000");
  const [days, setDays] = useState("1");
  const [minutes, setMinutes] = useState("30");
  const [permit, setPermit] = useState<PermitSingle & { owner: Address }>();
  const [textHex, setTextHex] = useState<Hex>();
  const [sig, setSig] = useState("");
  const [checks, setChecks] = useState<Check[]>();
  const [result, setResult] = useState<string>();
  const [err, setErr] = useState<string>();
  const [walletMsg, setWalletMsg] = useState<string>();

  async function build() {
    setErr(undefined);
    setResult(undefined);
    setChecks(undefined);
    setSig("");
    setWalletMsg(undefined);
    if (!owner) return setErr("Choose an owner in section 2 first.");
    if (!isAddress(token) || !isAddress(spender)) return setErr("Token and spender must be 0x addresses.");
    const nonce = (await client.readContract({ address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "nonces", args: [owner] })) as bigint;
    const p: PermitSingle = {
      token: getAddress(token),
      spender: getAddress(spender),
      amount: BigInt(amount),
      expiration: Number(now() + BigInt(Math.round(Number(days) * 86400))),
      nonce,
      sigDeadline: now() + BigInt(Math.round(Number(minutes) * 60)),
    };
    setPermit({ ...p, owner });
    setTextHex(await permitTextFor(owner, p));
  }

  /** Two independent checks: QoreSign in this browser, then the deployed contract via eth_call. */
  async function check(signature = sig) {
    if (!permit || !textHex) return;
    const s = signature.trim();
    setResult(undefined);
    if (!/^0x[0-9a-fA-F]+$/.test(s)) return setResult("Paste the signature as 0x… hex.");
    const ks = await keyStatus(permit.owner);
    const local = ks.ready && pqVerify(hexToBytes(ks.pubkey), qoreSignBytes(textHex), hexToBytes(s as Hex));
    const r = await outcome(simulatePermit(permit.owner, permit, s as Hex));
    setChecks([
      { label: "QoreSign, in your browser", detail: "pqVerify against the key pqcKeyStatus returns for the owner", status: local ? "ok" : "bad", value: ks.ready ? (local ? "valid" : "invalid") : "owner has no usable key" },
      { label: "PQPermit.permit on chain", detail: "eth_call to the deployed contract (pqcVerify precompile)", status: r === "OK" ? "ok" : "bad", value: r === "OK" ? "accepted" : r },
    ]);
    setResult(r);
  }

  function signDemo() {
    if (!textHex) return;
    const s = bytesToHex(pqSign(demoKey().secretKey, qoreSignBytes(textHex)));
    setSig(s);
    check(s).catch((e) => setResult(String(e?.shortMessage ?? e)));
  }

  /** QoreX's native signArbitrary. Today QoreX refuses it before any prompt; the page shows what the wallet answers. */
  async function signQorex() {
    setWalletMsg(undefined);
    const native = getQorexNative();
    if (!native || !wallet || !textHex) return setWalletMsg("Connect QoreX in section 2 first.");
    try {
      const res = (await native.signArbitrary(CHAIN_ID, wallet.bech32, hexToBytes(textHex))) as unknown as { pq?: { signature?: string } };
      const pq = res?.pq?.signature; // QoreSign MessageSignature shape (base64 ML-DSA-87 signature)
      if (!pq) return setWalletMsg("QoreX answered without an ML-DSA-87 signature, so it can't authorise a permit.");
      const s = b64ToHex(pq);
      setSig(s);
      await check(s);
    } catch (e) {
      setWalletMsg(`QoreX answered: "${String((e as Error).message ?? e)}". Use the command below until it supports message signing.`);
    }
  }

  const isDemo = owner === DEMO.owner;
  const walletIsOwner = !!wallet && owner === wallet.evm;
  const json =
    permit ? JSON.stringify({ owner: permit.owner, permit: { token: permit.token, spender: permit.spender, amount: permit.amount.toString(), expiration: permit.expiration, nonce: permit.nonce.toString(), sigDeadline: permit.sigDeadline.toString() } }) : "";

  return (
    <section className="card">
      <h2>3 · Compose, sign and check a permit</h2>
      <p className="small">The contract itself writes the text the owner signs (<code>permitText</code>), so what you read is exactly what is verified.</p>
      <div className="grid">
        <div>
          <label>Token</label>
          <input value={token} onChange={(e) => setToken(e.target.value.trim())} spellCheck={false} />
        </div>
        <div>
          <label>Spender</label>
          <input value={spender} onChange={(e) => setSpender(e.target.value.trim())} spellCheck={false} />
        </div>
        <div>
          <label>Amount (raw units; dUSD has 6 decimals)</label>
          <input value={amount} onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ""))} />
        </div>
        <div>
          <label>Allowance lasts (days) · signature valid for (minutes)</label>
          <div className="grid">
            <input value={days} onChange={(e) => setDays(e.target.value)} />
            <input value={minutes} onChange={(e) => setMinutes(e.target.value)} />
          </div>
        </div>
      </div>
      <button onClick={() => build().catch((e) => setErr(String(e?.shortMessage ?? e)))}>Build permit for {owner ? short(owner) : "…"}</button>
      {err && <div className="note">{err}</div>}
      {textHex && permit && (
        <>
          <label>What the owner signs: QoreSign message-signing-v1, "qorechain-msg-v1|{CHAIN_ID}|" + this text</label>
          <pre>{hexToString(textHex)}</pre>

          <h3>Sign it</h3>
          {isDemo ? (
            <>
              <button onClick={signDemo}>Sign here with the public demo key</button>
              <p className="small">
                Signs with <code>@qorechain/qoresign</code> in this browser. The demo owner's seed is public on purpose and it holds no tokens.
              </p>
            </>
          ) : (
            <p className="small">
              No wallet? Choose <b>Use the public demo owner</b> in section 2 and build again: this page can sign for it.
            </p>
          )}
          {walletIsOwner && (
            <>
              <button className="ghost" onClick={() => signQorex()}>Sign with QoreX</button>
              {walletMsg && <div className="note">{walletMsg}</div>}
            </>
          )}
          {!isDemo && (
            <div className="note">
              <b>Your own key:</b> QoreX refuses <code>signArbitrary</code> for now, and the text is already in its message-signing-v1 format, so the
              contract needs no change when it ships. Until then, the owner signs with <code>@qorechain/qoresign</code>:
              <pre>{`cd live && npm ci
npm run sign-permit -- '${json}'`}</pre>
              It prints the 4,627-byte ML-DSA-87 signature (needs <code>OWNER_MNEMONIC</code> in <code>live/.env</code>).
            </div>
          )}

          <label>Signature (0x…)</label>
          <textarea value={sig} onChange={(e) => setSig(e.target.value)} spellCheck={false} placeholder="0x…" />
          <button onClick={() => check().catch((e) => setResult(String(e?.shortMessage ?? e)))}>Check</button>
          {checks && <Checks items={checks} />}
          {result && (
            <div className={`verdict ${result === "OK" ? "ok" : "bad"}`}>
              {result === "OK" ? (
                <>
                  <b>Valid.</b> The contract accepts this signature: anyone can relay <code>permit()</code> and the owner pays no gas. Change one
                  character of the signature and check again to see it refused.
                </>
              ) : (
                <>
                  <b>Refused:</b> <code>{result}</code>
                </>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}

export function App() {
  const [owner, setOwner] = useState<Address>();
  const [wallet, setWallet] = useState<Wallet>();
  return (
    <div className="page">
      <header>
        <h1>PQ Permit</h1>
        <p className="lead">
          Gasless token approvals signed with ML-DSA-87. QoreChain's EVM windows protect <i>transactions</i>, not <i>signatures</i>: an EIP-2612
          permit signed by a leaked ECDSA key still drains a token. PQ Permit makes the signature post-quantum. Built with{" "}
          <code>@qorechain/qoresign</code>, <code>@qorechain/qorex-types</code> and <code>@qorechain/pqc</code>.
        </p>
        <div className="links">
          <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <a href={VIDEO} target="_blank" rel="noreferrer">Video (2:50)</a>
          <a href={`${REPO}/blob/main/docs/TESTNET_RUN.md`} target="_blank" rel="noreferrer">Testnet run</a>
          <a href={`${REPO}/blob/main/docs/AUDIT.md`} target="_blank" rel="noreferrer">QCAI audit</a>
          <span className="small">PQPermit {short(LIVE.pqPermit)} on qorechain-diana</span>
        </div>
      </header>
      <LiveProof />
      <Account owner={owner} setOwner={setOwner} wallet={wallet} setWallet={setWallet} />
      <Compose owner={owner} wallet={wallet} />
      <footer>Testnet only (qorechain-diana, EVM chain 9800). Testnet QOR has no value. MIT licence.</footer>
    </div>
  );
}
