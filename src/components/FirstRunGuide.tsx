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
import { Button, Modal, Space, Steps, Typography } from "antd";
import type { Lang } from "../models";

type Props = {
  open: boolean;
  lang: Lang;
  t: Record<string, string>;
  onClose: () => void;
};

const STEP_KEYS = ["welcome", "privacy", "evidence", "tools"] as const;

export function FirstRunGuide({ open, lang, t, onClose }: Props) {
  const [current, setCurrent] = React.useState(0);
  const isLast = current === STEP_KEYS.length - 1;
  const stepKey = STEP_KEYS[current];

  const handleClose = React.useCallback(() => {
    setCurrent(0);
    onClose();
  }, [onClose]);

  const next = () => setCurrent((value) => Math.min(value + 1, STEP_KEYS.length - 1));
  const prev = () => setCurrent((value) => Math.max(value - 1, 0));

  const items = STEP_KEYS.map((key) => ({ title: t[`firstRun_${key}_label`] }));

  return (
    <Modal
      open={open}
      onCancel={handleClose}
      footer={null}
      centered
      width={680}
      title={t.firstRunTitle}
      destroyOnClose
    >
      <Steps current={current} items={items} size="small" style={{ marginBottom: 24 }} />
      <Typography.Paragraph style={{ fontSize: 15, minHeight: 104, lineHeight: 1.7 }}>
        <strong style={{ fontSize: 16 }}>{t[`firstRun_${stepKey}_title`]}</strong>
        <br />
        {t[`firstRun_${stepKey}_body`]}
      </Typography.Paragraph>
      <Space style={{ display: "flex", justifyContent: "space-between" }}>
        <Button onClick={handleClose}>{t.firstRunSkip}</Button>
        <Space>
          {current > 0 && <Button onClick={prev}>{t.firstRunBack}</Button>}
          {isLast ? (
            <Button type="primary" onClick={handleClose}>
              {t.firstRunStart}
            </Button>
          ) : (
            <Button type="primary" onClick={next}>
              {t.firstRunNext}
            </Button>
          )}
        </Space>
      </Space>
    </Modal>
  );
}
