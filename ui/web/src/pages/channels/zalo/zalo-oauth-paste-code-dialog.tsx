import { useEffect, useState } from "react";
import { ExternalLink, Copy, Check } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useWsCall } from "@/hooks/use-ws-call";

// TODO i18n: phase-07 will replace hard-coded English strings with i18n keys.
// For now we ship literals so the build stays clean (per phase-06 plan §Risk).

interface ZaloOAuthPasteCodeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  instanceId: string;
  instanceName: string;
  onSuccess: () => void;
}

interface ConsentResp {
  url: string;
  state: string;
}

interface ExchangeResp {
  ok: boolean;
  oa_id?: string;
  expires_at?: string;
}

export function ZaloOAuthPasteCodeDialog({
  open,
  onOpenChange,
  instanceId,
  instanceName,
  onSuccess,
}: ZaloOAuthPasteCodeDialogProps) {
  const consent = useWsCall<ConsentResp>("channels.instances.zalo_oauth.consent_url");
  const exchange = useWsCall<ExchangeResp>("channels.instances.zalo_oauth.exchange_code");

  const [code, setCode] = useState("");
  const [state, setState] = useState("");
  const [url, setUrl] = useState("");
  const [copied, setCopied] = useState(false);
  const [done, setDone] = useState(false);

  // Fetch consent URL when the dialog opens.
  useEffect(() => {
    if (!open) return;
    consent
      .call({ instance_id: instanceId })
      .then((resp) => {
        setUrl(resp.url);
        setState(resp.state);
      })
      .catch(() => {
        // error surfaced via consent.error below
      });
    // intentionally not depending on `consent` (referential identity churns
    // every render via useCallback on the call); instanceId is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, instanceId]);

  // Reset on close.
  useEffect(() => {
    if (open) return;
    setCode("");
    setState("");
    setUrl("");
    setCopied(false);
    setDone(false);
    consent.reset();
    exchange.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Auto-close shortly after success.
  useEffect(() => {
    if (!done) return;
    onSuccess();
    const id = setTimeout(() => onOpenChange(false), 1500);
    return () => clearTimeout(id);
  }, [done, onSuccess, onOpenChange]);

  const submitting = exchange.loading;
  const loadingConsent = consent.loading;

  async function handleCopy() {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable on http://; user can still copy from input.
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
      // exchange.error captures it; UI shows below
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!submitting) onOpenChange(v); }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Connect Zalo OA — {instanceName}</DialogTitle>
          <DialogDescription>
            Authorize the Official Account, then paste the code returned by Zalo.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-5 py-2">
          {/* Step 1 — Consent */}
          <section className="space-y-2">
            <h3 className="text-sm font-medium">Step 1 — Authorize</h3>
            {loadingConsent && (
              <p className="text-sm text-muted-foreground">Generating consent URL…</p>
            )}
            {consent.error && (
              <p className="text-sm text-destructive">{consent.error.message ?? "Failed to fetch consent URL"}</p>
            )}
            {url && (
              <div className="flex items-center gap-2">
                <Input value={url} readOnly className="text-xs" />
                <Button type="button" variant="outline" size="sm" onClick={handleCopy} aria-label="Copy URL">
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
                <Button type="button" variant="outline" size="sm" onClick={handleOpenInTab} aria-label="Open in new tab">
                  <ExternalLink className="h-4 w-4" />
                </Button>
              </div>
            )}
          </section>

          {/* Step 2 — Paste code */}
          <section className="space-y-2">
            <h3 className="text-sm font-medium">Step 2 — Paste authorization code</h3>
            <p className="text-xs text-muted-foreground">
              After approving, Zalo redirects to a placeholder page; copy the <code>code</code> query parameter from the URL bar and paste it below.
            </p>
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="authorization_code from Zalo redirect"
              disabled={submitting || done}
              autoFocus
            />
            {exchange.error && (
              <p className="text-sm text-destructive">{exchange.error.message ?? "Code exchange failed"}</p>
            )}
            {done && (
              <p className="text-sm text-green-600 font-medium">Connected — closing…</p>
            )}
          </section>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!code.trim() || !state || submitting || done}>
            {submitting ? "Connecting…" : "Connect"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
