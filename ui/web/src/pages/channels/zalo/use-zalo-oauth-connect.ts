import { useEffect, useState } from "react";
import { useWsCall } from "@/hooks/use-ws-call";

// Shared state machine for the zalo_oauth paste-code consent flow. Consumed
// by both the ReauthDialog (triggered from the row) and the WizardAuthStep
// (auto-triggered after row creation).

interface ConsentResp {
  url: string;
  state: string;
}

interface ExchangeResp {
  ok: boolean;
  oa_id?: string;
  expires_at?: string;
}

export interface UseZaloOAuthConnectResult {
  url: string;
  code: string;
  setCode: (c: string) => void;
  state: string;
  copied: boolean;
  done: boolean;
  handleCopy: () => Promise<void>;
  handleOpenInTab: () => void;
  handleSubmit: () => Promise<void>;
  submitting: boolean;
  loadingConsent: boolean;
  consentError: string | null;
  exchangeError: string | null;
  reset: () => void;
}

/**
 * @param instanceId   Channel-instance UUID to authorize.
 * @param active       Gate state fetching — set to true once the flow is visible
 *                     (dialog open / wizard step active). Avoids racing WS calls
 *                     while the dialog is still mounting.
 * @param onSuccess    Invoked once when exchange completes successfully.
 */
export function useZaloOAuthConnect(
  instanceId: string,
  active: boolean,
  onSuccess: () => void,
): UseZaloOAuthConnectResult {
  const consent = useWsCall<ConsentResp>("channels.instances.zalo_oauth.consent_url");
  const exchange = useWsCall<ExchangeResp>("channels.instances.zalo_oauth.exchange_code");

  const [code, setCode] = useState("");
  const [state, setState] = useState("");
  const [url, setUrl] = useState("");
  const [copied, setCopied] = useState(false);
  const [done, setDone] = useState(false);

  // Fetch consent URL once the flow becomes active.
  useEffect(() => {
    if (!active || !instanceId) return;
    consent
      .call({ instance_id: instanceId })
      .then((resp) => {
        setUrl(resp.url);
        setState(resp.state);
      })
      .catch(() => {
        // error captured on consent.error
      });
    // consent.call identity churns per render; the instanceId+active trigger is intentional
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, instanceId]);

  // Reset state when the flow goes inactive.
  useEffect(() => {
    if (active) return;
    setCode("");
    setState("");
    setUrl("");
    setCopied(false);
    setDone(false);
    consent.reset();
    exchange.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // Fire onSuccess exactly once when exchange completes.
  useEffect(() => {
    if (!done) return;
    onSuccess();
  }, [done, onSuccess]);

  async function handleCopy() {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable on http://; user can still copy manually
    }
  }

  function handleOpenInTab() {
    if (!url) return;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  async function handleSubmit() {
    if (!code.trim() || !state) return;
    try {
      const resp = await exchange.call({
        instance_id: instanceId,
        code: code.trim(),
        state,
      });
      if (resp?.ok) setDone(true);
    } catch {
      // error captured on exchange.error
    }
  }

  return {
    url,
    code,
    setCode,
    state,
    copied,
    done,
    handleCopy,
    handleOpenInTab,
    handleSubmit,
    submitting: exchange.loading,
    loadingConsent: consent.loading,
    consentError: consent.error?.message ?? null,
    exchangeError: exchange.error?.message ?? null,
    reset: () => {
      consent.reset();
      exchange.reset();
      setCode("");
      setState("");
      setUrl("");
      setDone(false);
    },
  };
}
