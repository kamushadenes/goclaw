import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import type { WizardAuthStepProps } from "../channel-wizard-registry";
import { useZaloOAuthConnect } from "./use-zalo-oauth-connect";
import { ZaloOAuthConnectBody } from "./zalo-oauth-connect-body";

// Paste-code consent step rendered inside the create wizard dialog after
// the channel_instance row has been persisted. Mounts active → hook fetches
// consent URL immediately so the user sees the Authorize button without
// an extra click.
export function ZaloOAuthAuthStep({ instanceId, onComplete, onSkip }: WizardAuthStepProps) {
  const { t } = useTranslation("channels");
  const flow = useZaloOAuthConnect(instanceId, true /* always active in wizard */, onComplete);

  const canSubmit = flow.code.trim() !== "" && flow.state !== "" && !flow.submitting && !flow.done;

  return (
    <>
      <ZaloOAuthConnectBody flow={flow} />
      <DialogFooter>
        <Button variant="outline" onClick={onSkip} disabled={flow.submitting}>
          {t("zaloOauth.cancel")}
        </Button>
        <Button onClick={flow.handleSubmit} disabled={!canSubmit}>
          {flow.submitting ? t("zaloOauth.connecting") : t("zaloOauth.connect")}
        </Button>
      </DialogFooter>
    </>
  );
}
