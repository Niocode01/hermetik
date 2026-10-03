import { useCallback, useEffect, useRef, useState } from "react";
import { getAuthClient, makeAccessActor, II_URL } from "./ic";
import type { F2Entitlement, F2ProvisionState } from "./ic";
import { ChatWorkspace } from "./chat/workspace";
import { useI18n } from "./i18n";

type Status =
  | "idle"
  | "logging-in"
  | "checking"
  | "denied"
  | "needs-payment"
  | "provisioning"
  | "allowed"
  | "error";

// Polling del contenedor mientras está Pending: el provisioner lo activa
// fuera de banda (admin/set_container) y el frontend lo descubre aquí.
const PROVISION_POLL_MS = 5000;
const PROVISION_POLL_MAX = 60; // 5 min máx; luego el usuario reintenta a mano.

function containerUrl(s: F2ProvisionState | null): string | null {
  if (!s || !("Active" in s.status)) return null;
  return s.url.length === 1 ? s.url[0] : null;
}

// Helpers F2: formato de ICP y de subcuenta (puros, testeables).
export function formatIcp(e8s: bigint): string {
  const neg = e8s < 0n;
  const v = neg ? -e8s : e8s;
  const whole = v / 100_000_000n;
  const frac = (v % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole.toString()}${frac ? "." + frac : ""} ICP`;
}

export function subaccountHex(sub: number[]): string {
  return sub.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Estado de atestación del enclave (ADR-01): lo que la UI pinta de forma
// PERMANENTE. Se deriva de `attestation_ref` del directorio certificado
// (ProvisionState): el provisioner publica `dev-unattested:` en desarrollo y
// una referencia de quote real cuando haya TEE.
export type AttestationUiState = "attested" | "dev-unattested" | "unknown";

export function deriveAttestationState(ref: [] | [string]): AttestationUiState {
  if (ref.length === 0) return "unknown";
  return ref[0].startsWith("dev-unattested:") ? "dev-unattested" : "attested";
}

export default function App() {
  const { lang, setLang, t } = useI18n();
  const [status, setStatus] = useState<Status>("idle");
  const [principal, setPrincipal] = useState<string>("");
  const [credential, setCredential] = useState<string>("");
  const [error, setError] = useState<string>("");
  // F2: entitlement + pago + provisioning.
  const [entitlement, setEntitlement] = useState<F2Entitlement | null>(null);
  const [payAmount, setPayAmount] = useState<bigint>(0n);
  const [paySubaccount, setPaySubaccount] = useState<number[]>([]);
  const [container, setContainer] = useState<F2ProvisionState | null>(null);
  void container;
  const [attestationState, setAttestationState] = useState<AttestationUiState>("unknown");
  const [provisionTries, setProvisionTries] = useState(0);
  const pollRef = useRef<number | null>(null);
  // Identidad II para refrescar la credencial nb2 (issue_credential) al
  // expirar/401 sin pedir un login nuevo.
  const identityRef = useRef<import("@dfinity/agent").Identity | null>(null);

  // Al recargar: si AuthClient ya tiene identidad, re-verificar allowlist.
  useEffect(() => {
    (async () => {
      try {
        const client = await getAuthClient();
        if (await client.isAuthenticated()) {
          await checkAccess(client.getIdentity());
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setStatus("error");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // Al desmontar: no dejar el polling vivo.
  useEffect(() => () => stopPolling(), [stopPolling]);

  const enterWithCredential = async (
    actor: Awaited<ReturnType<typeof makeAccessActor>>,
  ) => {
    // Allowlisted → emitir credencial nb2 (TTL 8h).
    const cred = await actor.issue_credential();
    setCredential(cred);
    setStatus("allowed");
  };

  // Tras el pago (o si ya hay entitlement): pedir contenedor y seguir su
  // estado. Si ya está Active → directo al chat; si Pending → polling.
  const followProvisioning = async (
    actor: Awaited<ReturnType<typeof makeAccessActor>>,
  ) => {
    const st = await actor.get_my_container();
    setContainer(st);
    setAttestationState(deriveAttestationState(st.attestation_ref));
    if (containerUrl(st)) {
      stopPolling();
      await enterWithCredential(actor);
      return;
    }
    setStatus("provisioning");
    setProvisionTries(0);
    stopPolling();
    let tries = 0;
    pollRef.current = window.setInterval(async () => {
      tries += 1;
      setProvisionTries(tries);
      try {
        const cur = await actor.get_my_container();
        setContainer(cur);
        setAttestationState(deriveAttestationState(cur.attestation_ref));
        if (containerUrl(cur)) {
          stopPolling();
          await enterWithCredential(actor);
        } else if (tries >= PROVISION_POLL_MAX) {
          stopPolling();
        }
      } catch (e) {
        // Un fallo de red no tumba el polling; el siguiente tick reintenta.
        console.warn("provision poll failed, retrying", e);
      }
    }, PROVISION_POLL_MS);
  };

  const refreshAfterPayment = async () => {
    const identity = identityRef.current;
    if (!identity) return;
    setStatus("checking");
    setError("");
    try {
      const actor = await makeAccessActor(identity);
      const ent = await actor.get_my_entitlement();
      setEntitlement(ent);
      if (!ent.active) {
        setStatus("needs-payment");
        return;
      }
      await actor.request_provision(ent.tier || 1);
      await followProvisioning(actor);
    } catch (e) {
      setError(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
      setStatus("error");
    }
  };

  const checkAccess = async (identity: import("@dfinity/agent").Identity) => {
    setStatus("checking");
    setError("");
    try {
      identityRef.current = identity;
      const actor = await makeAccessActor(identity);
      const me = await actor.me();
      setPrincipal(me.toText());
      const allowed = await actor.is_allowed_caller();
      if (!allowed) {
        setCredential("");
        setStatus("denied");
        return;
      }
      // F2: con allowlist, el paso siguiente es la SUSCRIPCIÓN, no el chat.
      // (La allowlist sola ya no abre el chat: el producto es pago + vault.)
      const ent = await actor.get_my_entitlement();
      setEntitlement(ent);
      if (!ent.active) {
        const [amount, sub] = await actor.get_payment_info(1);
        setPayAmount(amount);
        setPaySubaccount(sub);
        setStatus("needs-payment");
        return;
      }
      await actor.request_provision(ent.tier || 1);
      await followProvisioning(actor);
    } catch (e) {
      setError(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
      setStatus("error");
    }
  };

  const login = useCallback(async () => {
    setStatus("logging-in");
    setError("");
    try {
      const client = await getAuthClient();
      await client.login({
        identityProvider: II_URL,
        // Sin derivationOrigin: es para "login como otro origen".
        // Sin windowOpenerFeatures → misma pestaña (popups bloqueados en headless).
        onSuccess: async () => {
          await checkAccess(client.getIdentity());
        },
        onError: (e) => {
          setError(e ?? t("app.loginFailed"));
          setStatus("error");
        },
      });
    } catch (e) {
      setError(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
      setStatus("error");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const logout = useCallback(async () => {
    stopPolling();
    const client = await getAuthClient();
    await client.logout();
    identityRef.current = null;
    setPrincipal("");
    setCredential("");
    setEntitlement(null);
    setContainer(null);
    setStatus("idle");
  }, [stopPolling]);

  // Credencial nb2 fresca para el workspace (re-conexión al expirar/401).
  const refreshCredential = useCallback(async (): Promise<string> => {
    const identity = identityRef.current;
    if (!identity) throw new Error(t("app.noIdentity"));
    const actor = await makeAccessActor(identity);
    const cred = await actor.issue_credential();
    setCredential(cred);
    return cred;
  }, [t]);

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* portapapeles no disponible: el usuario copia a mano */
    }
  };

// Shell Ascari: header nocturno + superficie principal.
  const shell = (
    <div className="workspace">
      <header className="workspace-header">
        <div className="header-left">
          <span className="header-brand">
            <img src="/logo.png" alt="Hermetik Agent" className="brand-logo" />
            hermetik agent<span className="brand-dot">.</span>
          </span>
          <span>{t("header.beta")}</span>
        </div>
        <div className="header-right">
          {/* Estado de atestación PERMANENTE (ADR-01): se pinta siempre, no
              solo al conectar. El modo dev se muestra en ámbar y con el aviso
              en el tooltip; nunca se oculta ni se maquilla de "verificado". */}
          <span
            className={`connection attest${attestationState === "attested" ? " ok" : attestationState === "dev-unattested" ? " warn" : ""}`}
            role="status"
            title={attestationState === "dev-unattested" ? t("attest.devWarning") : undefined}
          >
            {attestationState === "attested"
              ? t("attest.attested")
              : attestationState === "dev-unattested"
                ? t("attest.devUnattested")
                : t("attest.unknown")}
          </span>
          {status === "allowed" ? (
            <>
              <span className="connection ok stacked" role="status"><span>{t("header.verified1")}</span><br /><span>{t("header.verified2")}</span></span>
              <button className="btn btn-sm" onClick={logout}>{t("header.signOut")}</button>
            </>
          ) : status === "checking" || status === "logging-in" ? (
            <span className="connection" role="status">{t("header.verifying")}</span>
          ) : (
            <span className="connection" role="status">{t("header.notConnected")}</span>
          )}
          <label className="lang-switch" aria-label={t("header.langLabel")}>
            <button
              type="button"
              className={`lang-btn${lang === "es" ? " active" : ""}`}
              onClick={() => setLang("es")}
              aria-pressed={lang === "es"}
            >
              ES
            </button>
            <button
              type="button"
              className={`lang-btn${lang === "en" ? " active" : ""}`}
              onClick={() => setLang("en")}
              aria-pressed={lang === "en"}
            >
              EN
            </button>
          </label>
        </div>
      </header>
      <main className={`main-surface${status === "idle" || status === "logging-in" ? " landing-scroll" : ""}`}>
        {(status === "idle" || status === "logging-in") && (
          <>
            {/* Fondo de vídeo en loop (mp4 h264, sin sonido). La imagen JPG
                queda como poster/fallback mientras carga o si el móvil no
                reproduce vídeo. El velo oscuro va por CSS encima. */}
            <video
              className="landing-video"
              src="/landing-bg.mp4"
              poster="/landing-bg.jpg"
              autoPlay
              muted
              loop
              playsInline
              preload="metadata"
              aria-hidden="true"
            />
            <div className="landing-veil" aria-hidden="true" />
            <section className="vault-entry">
              <div className="entry-logo" aria-hidden="true">
                <img src="/logo.png" alt="" />
              </div>
              <p className="eyebrow">The perfect agent</p>
              <h1 className="landing-hero">{t("landing.title").split("\n").map((line, i, a) => (<span key={i}>{line}{i < a.length - 1 && <br />}</span>))}</h1>
              <p className="entry-copy">{t("landing.copy")}</p>
              <form className="vault-form" onSubmit={(e) => { e.preventDefault(); void login(); }}>
                <button type="submit" disabled={status === "logging-in"}>
                  {status === "logging-in" ? t("landing.opening") : t("landing.signIn")}
                </button>
              </form>
              <p className="fineprint">{t("landing.fineprint")}</p>
            </section>
            <section className="about-hermetik" aria-label={t("landing.aboutLabel")}>
              <p className="eyebrow">{t("landing.aboutLabel")}</p>
              <h2>{t("landing.aboutTitle")}</h2>
              <p className="about-lead">
                {t("landing.aboutLead")}
              </p>
              <ul className="about-grid">
                <li>
                  <h3>{t("landing.f1t")}</h3>
                  <p>{t("landing.f1d")}</p>
                </li>
                <li>
                  <h3>{t("landing.f2t")}</h3>
                  <p>{t("landing.f2d")}</p>
                </li>
                <li>
                  <h3>{t("landing.f3t")}</h3>
                  <p>{t("landing.f3d")}</p>
                </li>
                <li>
                  <h3>{t("landing.f4t")}</h3>
                  <p>{t("landing.f4d")}</p>
                </li>
                <li>
                  <h3>{t("landing.f5t")}</h3>
                  <p>{t("landing.f5d")}</p>
                </li>
                <li>
                  <h3>{t("landing.f6t")}</h3>
                  <p>{t("landing.f6d")}</p>
                </li>
              </ul>
            </section>
          </>
        )}
        {status === "checking" && (
          <section className="vault-entry">
            <p className="eyebrow">{t("access.brand")}</p>
            <h1>{t("access.checking")}</h1>
            <p className="entry-copy">{t("access.checkingCopy")}</p>
          </section>
        )}
        {status === "denied" && (
          <section className="vault-entry">
            <div className="entry-logo entry-logo-sm" aria-hidden="true">
              <img src="/logo.png" alt="" />
            </div>
            <p className="eyebrow">Access</p>
            <h1>{t("access.title")}</h1>
            <p className="entry-copy">
              {t("access.yourPrincipal")} <code>{principal}</code> {t("access.copy")}
            </p>
            <pre className="approval-command">
              dfx canister --network ic call access grant '(principal "{principal}")'
            </pre>
            <div className="chat-toolbar">
              <button className="btn" onClick={() => void copy(principal)}>{t("access.copyBtn")}</button>
              <button className="btn" onClick={login}>{t("access.retry")}</button>
              <button className="btn" onClick={logout}>{t("header.signOut")}</button>
            </div>
          </section>
        )}
        {status === "needs-payment" && (
          <section className="vault-entry">
            <p className="eyebrow">{t("pay.brand")}</p>
            <h1>{t("pay.title")}</h1>
            <p className="entry-copy">{t("pay.copy")}</p>
            <div className="pay-box" role="group" aria-label={t("pay.title")}>
              <p>
                {t("pay.amount")} <code>{formatIcp(payAmount)}</code>
              </p>
              <p>
                {t("pay.subaccount")} <code className="pay-sub">{subaccountHex(paySubaccount)}</code>
              </p>
              <p className="fineprint">{t("pay.howto")}</p>
            </div>
            <p className="entry-copy">
              {t("access.yourPrincipal")} <code>{principal}</code>
            </p>
            <div className="chat-toolbar">
              <button className="btn" onClick={() => void copy(subaccountHex(paySubaccount))}>{t("pay.copySub")}</button>
              <button className="btn" onClick={() => void refreshAfterPayment()}>{t("pay.ivePaid")}</button>
              <button className="btn" onClick={logout}>{t("header.signOut")}</button>
            </div>
          </section>
        )}
        {status === "provisioning" && (
          <section className="vault-entry">
            <p className="eyebrow">{t("prov.brand")}</p>
            <h1>{t("prov.title")}</h1>
            <p className="entry-copy">
              {provisionTries >= PROVISION_POLL_MAX
                ? t("prov.timeout")
                : t("prov.copy")}
            </p>
            {entitlement && (
              <p className="entry-copy">
                {t("prov.tier")} <code>{entitlement.tier}</code>
              </p>
            )}
            <div className="chat-toolbar">
              <button className="btn" onClick={() => void refreshAfterPayment()}>{t("prov.retry")}</button>
              <button className="btn" onClick={logout}>{t("header.signOut")}</button>
            </div>
          </section>
        )}
        {status === "allowed" && (
          <>
            <div className="chat-toolbar">
              <span className="toolbar-meta">{t("access.user")} <code>{principal}</code></span>
            </div>
            {/* X-Nebulock-User = principal II: el gateway nb2 exige que sea
                EXACTAMENTE el principal de la credencial (403 si no). */}
            <ChatWorkspace
              user={principal}
              initialCredential={credential}
              refreshCredential={refreshCredential}
              onCredentialRefreshed={setCredential}
            />
          </>
        )}
        {status === "error" && (
          <div className="notice error" role="alert">Error: {error}</div>
        )}
      </main>
    </div>
  );
  return shell;
}
