import type { PropsWithChildren } from "react";
import { useState } from "react";

type ReauthBoundaryProps = PropsWithChildren<{
  required: boolean;
  onReauthenticate: () => Promise<void>;
}>;

export function ReauthBoundary({
  required,
  onReauthenticate,
  children,
}: ReauthBoundaryProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | undefined>();
  if (!required) {
    return children;
  }
  const reauthenticate = async () => {
    setPending(true);
    setError(undefined);
    try {
      await onReauthenticate();
    } catch {
      setError("重新认证失败，请重试");
    } finally {
      setPending(false);
    }
  };
  return (
    <section className="reauth-boundary">
      <p>此操作要求最近完成的身份认证。</p>
      {error === undefined ? null : <p role="alert">{error}</p>}
      <button
        type="button"
        disabled={pending}
        onClick={() => {
          void reauthenticate();
        }}
      >
        {pending ? "正在跳转…" : "重新认证"}
      </button>
    </section>
  );
}
