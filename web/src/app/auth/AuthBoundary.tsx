import type { PropsWithChildren } from "react";

type AuthBoundaryProps = PropsWithChildren<{
  error?: unknown;
  onRetry?: () => void;
}>;

export function AuthBoundary({
  error,
  onRetry,
  children,
}: AuthBoundaryProps) {
  if (error !== undefined && error !== null) {
    return (
      <main role="alert" aria-labelledby="auth-failure-title">
        <h1 id="auth-failure-title">安全登录初始化失败</h1>
        <p>无法验证浏览器配置或登录状态，应用保持关闭且不会匿名进入。</p>
        {onRetry === undefined ? null : (
          <button type="button" onClick={onRetry}>
            重新加载安全配置
          </button>
        )}
      </main>
    );
  }
  return children;
}
