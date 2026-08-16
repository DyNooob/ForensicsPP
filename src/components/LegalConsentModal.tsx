/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.forensicspp.com
 * Platform: DigiForensics.cn
 * Project: https://github.com/DyNooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import React from "react";
import { Modal } from "antd";
import { CheckCircleFilled } from "@ant-design/icons";
import { AButton } from "./ui";
import type { Translation } from "../i18n";

type LegalConsentModalProps = {
  t: Translation;
  open: boolean;
  onAccept: () => void;
};

export function LegalConsentModal({ t, open, onAccept }: LegalConsentModalProps) {
  return (
    <Modal
      className="legal-consent-modal"
      open={open}
      centered
      width={520}
      title={t.legalNoticeTitle}
      closable={false}
      maskClosable={false}
      keyboard={false}
      footer={(
        <div className="legal-consent-actions">
          <AButton href="./legal.html" target="_blank" variant="outlined">{t.viewFullTerms}</AButton>
          <AButton variant="filled" onClick={onAccept}>{t.acceptTerms}</AButton>
        </div>
      )}
    >
      <p className="legal-consent-body">{t.legalNoticeBody}</p>
      <ul className="legal-consent-list">
        {[t.legalAuthorization, t.legalLawfulUse, t.legalOutputReview, t.legalDataCare].map((item) => (
          <li key={item}><CheckCircleFilled aria-hidden="true" /><span>{item}</span></li>
        ))}
      </ul>
    </Modal>
  );
}
