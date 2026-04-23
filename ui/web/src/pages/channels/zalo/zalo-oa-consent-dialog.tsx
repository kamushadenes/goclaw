import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useZaloOAConnect } from "./use-zalo-oa-connect";
import { ZaloOAConnectBody } from "./zalo-oa-connect-body";

interface ZaloOAConsentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  instanceId: string;
  instanceName: string;
  onSuccess: () => void;
}

export function ZaloOAConsentDialog({
  open,
  onOpenChange,
  instanceId,
  instanceName,
  onSuccess,
}: ZaloOAConsentDialogProps) {
  const { t } = useTranslation("channels");
  const flow = useZaloOAConnect(instanceId, open, onSuccess);

  // Auto-close the dialog shortly after success so the user sees the check.
  useEffect(() => {
    if (!flow.done) return;
    const id = setTimeout(() => onOpenChange(false), 1500);
    return () => clearTimeout(id);
  }, [flow.done, onOpenChange]);

  const canSubmit =
    flow.code.trim() !== "" && flow.state !== "" && !flow.submitting && !flow.done;

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!flow.submitting) onOpenChange(v); }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("zaloOauth.dialogTitle", { name: instanceName })}</DialogTitle>
          <DialogDescription>{t("zaloOauth.dialogDescription")}</DialogDescription>
        </DialogHeader>

        <ZaloOAConnectBody flow={flow} />

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={flow.submitting}>
            {t("zaloOauth.cancel")}
          </Button>
          <Button onClick={flow.handleSubmit} disabled={!canSubmit}>
            {flow.submitting ? t("zaloOauth.connecting") : t("zaloOauth.connect")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
