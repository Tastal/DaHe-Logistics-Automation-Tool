import { KeyRound, Save, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import type {
  AppServices,
  PlatformCredentialStatus,
} from "../../app/contracts";
import { Tooltip } from "../../components/Tooltip";
import { useToast } from "../../components/ToastContext";

export function CredentialSettings({ services }: { services: AppServices }) {
  const [status, setStatus] = useState<PlatformCredentialStatus | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [replacing, setReplacing] = useState(false);
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  useEffect(() => {
    let active = true;
    if (!services.loadPlatformCredentials) return;
    void services
      .loadPlatformCredentials()
      .then((next) => {
        if (active) setStatus(next);
      })
      .catch(() => {
        if (active) showToast("成丰登录信息状态读取失败。", "error");
      });
    return () => {
      active = false;
    };
  }, [services, showToast]);

  const save = async () => {
    if (!status || !services.savePlatformCredentials) return;
    setBusy(true);
    try {
      const next = await services.savePlatformCredentials({
        username: username.trim(),
        password,
        expectedRecordVersion: status.recordVersion,
      });
      setStatus(next);
      setUsername("");
      setPassword("");
      setReplacing(false);
      showToast("登录信息已保存。", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "登录信息保存失败。", "error");
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!status || !services.deletePlatformCredentials) return;
    setBusy(true);
    try {
      const next = await services.deletePlatformCredentials(status.recordVersion);
      setStatus(next);
      setUsername("");
      setPassword("");
      setReplacing(false);
      showToast("登录信息已删除。", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "登录信息删除失败。", "error");
    } finally {
      setBusy(false);
    }
  };

  if (!services.loadPlatformCredentials) return null;

  return (
    <section className="settings-section credential-settings" aria-labelledby="credential-settings-title">
      <div className="compact-section-heading">
        <div className="title-row">
          <KeyRound aria-hidden="true" size={20} />
          <h2 id="credential-settings-title">成丰登录</h2>
        </div>
      </div>
      <form
        className="credential-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <div className="credential-fields">
        <label>
          <span>成丰账号</span>
          <input
            autoComplete="off"
            maxLength={512}
            value={status?.configured && !replacing ? status.maskedUsername ?? "" : username}
            readOnly={Boolean(status?.configured && !replacing)}
            placeholder="输入完整账号"
            onFocus={() => {
              if (status?.configured && !replacing) {
                setReplacing(true);
                setUsername("");
                setPassword("");
              }
            }}
            onChange={(event) => setUsername(event.target.value)}
          />
        </label>
        <label>
          <span>成丰密码</span>
          <input
            autoComplete="new-password"
            maxLength={512}
            type="password"
            value={password}
            placeholder={status?.configured && !replacing ? "已保存，不显示明文" : "输入完整密码"}
            onFocus={() => {
              if (status?.configured && !replacing) {
                setReplacing(true);
                setUsername("");
                setPassword("");
              }
            }}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        </div>
        <div className="compact-actions">
          <Tooltip content="保存到当前 Windows 用户的安全凭据区。">
            <button
              className="button primary"
              type="submit"
              disabled={busy || !status || !username.trim() || !password || (status.configured && !replacing)}
            >
              <Save aria-hidden="true" size={17} />
              保存登录信息
            </button>
          </Tooltip>
          {status?.configured ? (
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={() => void remove()}
            >
              <Trash2 aria-hidden="true" size={17} />
              删除登录信息
            </button>
          ) : null}
        </div>
      </form>
    </section>
  );
}
