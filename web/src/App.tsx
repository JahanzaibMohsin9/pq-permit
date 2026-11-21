import { mldsa87 } from "@qorechain/pqc";
import { useEffect, useState } from "react";
import { bytesToHex, decodeFunctionData, formatUnits, getAddress, hexToString, isAddress, toHex, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { bech32Decode } from "./bech32.ts";
import { LIVE, REPO, VIDEO, client, erc20Abi, keyStatus, outcome, pqPermitAbi, qoreSignBytes, simulatePermit, type PermitSingle } from "./chain.ts";

type Check = { label: string; detail?: string; status: "pending" | "ok" | "bad"; value?: string };
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
type Qorex = { native?: { enable(c: string): Promise<void>; getKey(c: string): Promise<{ bech32Address: string }> } };

function toEvm(input: string): Address | undefined {
  const s = input.trim();
  if (isAddress(s)) return getAddress(s);
  try {
    const { prefix, data } = bech32Decode(s);
    if (prefix === "qor" && data.length === 20) return getAddress(bytesToHex(data));
  } catch {
    /* not bech32 */
  }
  return undefined;
}

function Account({ owner, setOwner }: { owner?: Address; setOwner: (a?: Address) => void }) {
  const [input, setInput] = useState<string>(LIVE.owner);
  const [items, setItems] = useState<Check[]>([]);
  const [err, setErr] = useState<string>();
  const [token, setToken] = useState<string>(LIVE.dusd);
  const [spender, setSpender] = useState<string>(LIVE.relayer);
  const [allowance, setAllowance] = useState<string>();

  async function connect() {
    setErr(undefined);
    const q = (window as unknown as { qorex?: Qorex }).qorex?.native;
    if (!q) return setErr("QoreX not found. Install it and switch it to Testnet, or paste an address.");
    try {
      await q.enable("qorechain-diana");
      setInput((await q.getKey("qorechain-diana")).bech32Address);
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
      <p className="small">Any owner, as 0x or qor1. The defaults are the live demo owner, its token (dUSD) and its spender.</p>
      <label>Owner</label>
      <input value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} />
      <button className="ghost" onClick={connect}>Use my QoreX account</button>
      {err && <div className="note">{err}</div>}
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
function Compose({ owner }: { owner?: Address }) {
  const [token, setToken] = useState<string>(LIVE.dusd);
  const [spender, setSpender] = useState<string>(LIVE.relayer);
  const [amount, setAmount] = useState("1000000");
  const [days, setDays] = useState("1");
  const [minutes, setMinutes] = useState("30");
  const [permit, setPermit] = useState<PermitSingle>();
  const [text, setText] = useState<string>();
  const [sig, setSig] = useState("");
  const [result, setResult] = useState<string>();
  const [err, setErr] = useState<string>();

  async function build() {
    setErr(undefined);
    setResult(undefined);
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
    setPermit(p);
    setText(hexToString(await permitTextFor(owner, p)));
  }

  async function check() {
    if (!owner || !permit) return;
    const s = sig.trim();
    if (!/^0x[0-9a-fA-F]+$/.test(s)) return setResult("Paste the signature as 0x… hex.");
    const r = await outcome(simulatePermit(owner, permit, s as Hex));
    setResult(r === "OK" ? "OK" : r);
  }

  const json = permit && owner ? JSON.stringify({ owner, permit: { ...permit, amount: permit.amount.toString(), nonce: permit.nonce.toString(), sigDeadline: permit.sigDeadline.toString() } }) : "";

  return (
    <section className="card">
      <h2>3 · Compose and check a permit</h2>
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
      {text && (
        <>
          <label>What the owner signs (QoreSign message-signing-v1, prefixed with "qorechain-msg-v1|qorechain-diana|")</label>
          <pre>{text}</pre>
          <div className="note">
            <b>Signing:</b> QoreX doesn't support <code>signArbitrary</code> yet. The text above is already in its message-signing-v1 format, so the
            contract needs no change when QoreX does. Until then, the owner signs with <code>@qorechain/sdk</code>:
            <pre>{`cd live && npm ci
npm run sign-permit -- '${json}'`}</pre>
            It prints the 4,627-byte ML-DSA-87 signature (needs <code>OWNER_MNEMONIC</code> in <code>live/.env</code>).
          </div>
          <label>Signature (0x…)</label>
          <textarea value={sig} onChange={(e) => setSig(e.target.value)} spellCheck={false} placeholder="0x…" />
          <button onClick={() => check().catch((e) => setResult(String(e?.shortMessage ?? e)))}>Check on chain</button>
          {result && (
            <div className={`verdict ${result === "OK" ? "ok" : "bad"}`}>
              {result === "OK" ? (
                <>
                  <b>Valid.</b> The contract accepts this signature: anyone can relay <code>permit()</code> and the owner pays no gas.
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
  return (
    <div className="page">
      <header>
        <h1>PQ Permit</h1>
        <p className="lead">
          Gasless token approvals signed with ML-DSA-87. QoreChain's EVM windows protect <i>transactions</i>, not <i>signatures</i>: an EIP-2612
          permit signed by a leaked ECDSA key still drains a token. PQ Permit makes the signature post-quantum.
        </p>
        <div className="links">
          <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <a href={VIDEO} target="_blank" rel="noreferrer">Video (2:47)</a>
          <a href={`${REPO}/blob/main/docs/TESTNET_RUN.md`} target="_blank" rel="noreferrer">Testnet run</a>
          <a href={`${REPO}/blob/main/docs/AUDIT.md`} target="_blank" rel="noreferrer">QCAI audit</a>
          <span className="small">PQPermit {short(LIVE.pqPermit)} on qorechain-diana</span>
        </div>
      </header>
      <LiveProof />
      <Account owner={owner} setOwner={setOwner} />
      <Compose owner={owner} />
      <footer>Testnet only (qorechain-diana, EVM chain 9800). Testnet QOR has no value. MIT licence.</footer>
    </div>
  );
}
