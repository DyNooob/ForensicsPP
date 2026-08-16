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

export type HashBundle = {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  sha3: string;
  sm3: string;
};

export type Lang = "zh" | "en";
export type ThemeMode = "light" | "dark" | "auto";
export type AppCommand = {
  id: string;
  group: string;
  label: string;
  hint: string;
  meta?: string;
  keywords: string;
  run: () => void;
};

export type PngChunkInfo = {
  offset: number;
  dataOffset: number;
  endOffset: number;
  type: string;
  length: number;
  crc: string;
  computed: string;
  ok: boolean;
  ancillary: boolean;
  privateUse: boolean;
  safeToCopy: boolean;
  entropy: number;
  hexPreview: string;
  preview: string;
  risk: string[];
};

export type PngTextEntry = {
  chunk: string;
  offset: number;
  keyword: string;
  text: string;
  compressed: boolean;
};

export type PngAnalysis = {
  name: string;
  size: number;
  rows: Array<[string, string]>;
  chunks: PngChunkInfo[];
  textEntries: PngTextEntry[];
  findings: Array<{ level: string; title: string; detail: string }>;
  trailer: Uint8Array;
  trailerPreview: string;
  trailerSha256: string;
  trailerEntropy: number;
  trailerSignatures: Array<{ label: string; offset: number }>;
  repairNotes: string[];
};

export type ImageAutoInsight = {
  level: string;
  title: string;
  detail: string;
  action: string;
  previewLabel?: string;
  previewSrc?: string;
};

export type ImageDisplayItem = {
  level: string;
  label: string;
  src: string;
  role: string;
  reason: string;
  action: string;
  rows: Array<[string, string]>;
};

export type ImageDecodedSignal = {
  source: string;
  type: string;
  level: string;
  value: string;
  detail: string;
  rows: Array<[string, string]>;
};

export type ImageEvidenceBoardItem = {
  level: string;
  title: string;
  detail: string;
  action: string;
  previewLabel?: string;
  previewSrc?: string;
  rows: Array<[string, string]>;
};

export type ImagePriorityReveal = {
  level: string;
  title: string;
  result: string;
  reason: string;
  previewLabel?: string;
  previewSrc?: string;
  value?: string;
  rows: Array<[string, string]>;
};

export type ImageAutoAssessment = {
  level: string;
  title: string;
  subtitle: string;
  primaryAction: string;
  items: Array<{ label: string; value: string; level: string; detail: string }>;
};

export type ImageTriageRow = {
  area: string;
  verdict: string;
  level: string;
  evidence: string;
  display: string;
  action: string;
};

export type ImageScanStep = {
  stage: string;
  status: string;
  level: string;
  evidence: string;
  display: string;
  next: string;
  previewLabel?: string;
  previewSrc?: string;
};

export type ImageInfo = {
  name: string;
  size: number;
  type: string;
  decoded: boolean;
  width: number;
  height: number;
  dataUrl: string;
  repairedDataUrl: string;
  repairedContainerBytes: Uint8Array | null;
  repairStatus: string;
  recoveryRows: Array<[string, string]>;
  exif: Record<string, unknown>;
  structureRows: Array<[string, string]>;
  hiddenRows: Array<[string, string]>;
  trailerBytes: Uint8Array;
  trailerPreview: string;
  trailerText: string;
  lsbCandidates: Array<{ mode: string; text: string }>;
  hiddenPayloads: Array<{ label: string; source: string; offset: number; size: number; extension: string; mime: string; preview: string; bytes: Uint8Array }>;
  repairDownloads: Array<{ label: string; note: string; size: number; extension: string; mime: string; bytes: Uint8Array }>;
  pngTextEntries: PngTextEntry[];
  pngChunks: PngChunkInfo[];
  autoRevealPreviews: Array<{ label: string; src: string; detail: string }>;
  repairPreviewItems: Array<{ label: string; src: string; detail: string }>;
  channelDataUrls: {
    red: string;
    green: string;
    blue: string;
    alpha: string;
    lsb: string;
    lsbRed: string;
    lsbGreen: string;
    lsbBlue: string;
    lowBitHeatmap: string;
    noiseMap: string;
    bitPlanes: Array<{ label: string; src: string }>;
  };
};

export type PcapInfo = {
  name: string;
  size: number;
  signature: string;
  format: string;
  endian: string;
  version: string;
  snaplen: number | null;
  linkType: number | null;
  sha256: string;
  summary: PcapSummary | null;
  packets: PcapPacket[];
  conversations: PcapConversation[];
  tcpStreams: PcapTcpStream[];
  endpoints: PcapEndpointStat[];
  portStats: PcapPortStat[];
  httpItems: PcapHttpItem[];
  dnsItems: PcapDnsItem[];
  tlsItems: PcapTlsHandshake[];
  extractedFiles: PcapExtractedFile[];
  streamBytesLimited?: boolean;
  extractedBytesLimited?: boolean;
  iocs: IocRecord[];
  timeline: PcapTimelineBucket[];
  events: PcapTimelineEvent[];
  evidenceMatrix: PcapEvidenceMatrixRow[];
  briefing: string;
  findings: Array<{ level: string; title: string; detail: string }>;
};

export type PcapEvidenceMatrixRow = {
  area: string;
  verdict: string;
  level: string;
  metric: string;
  evidence: string;
  action: string;
};

export type SqlColumn = {
  name: string;
  type: string;
};

export type SqlTable = {
  name: string;
  columns: SqlColumn[];
  rows: Array<Record<string, string>>;
  insertRows: number;
};

export type SqlFinding = {
  table: string;
  column: string;
  type: string;
  sample: string;
};

export type SqlParseResult = {
  name: string;
  size: number;
  statementCount: number;
  tables: SqlTable[];
  findings: SqlFinding[];
};

export type ArchiveEntry = {
  name: string;
  directory: string;
  extension: string;
  role?: string;
  method: number;
  compressed: number;
  uncompressed: number;
  encrypted: boolean;
  crc: string;
  extractedSize?: number;
  sha256?: string;
  signature?: string;
  preview?: string;
  data?: Uint8Array;
  risk: string[];
};

export type ArchiveEvidenceRow = {
  area: string;
  count: string;
  level: string;
  primary: string;
  risk: string;
  action: string;
};

export type CaseEvidenceFile = {
  name: string;
  size: number;
  type: string;
  lastModified?: string;
  sha256?: string;
};

export type CaseTimelineEvent = Pick<TimelineEvent, "iso" | "local" | "raw" | "format" | "line" | "source" | "context" | "epochMs">;

export type CaseNote = {
  id: string;
  tool: string;
  title: string;
  content: string;
  summary?: string;
  markdown?: string;
  description?: string;
  route?: string;
  sourceUrl?: string;
  contentSha256?: string;
  evidenceFiles?: CaseEvidenceFile[];
  timelineEvents?: CaseTimelineEvent[];
  createdAt: string;
};

export type CaseRiskLevel = "critical" | "review" | "normal";

export type CaseReportMeta = {
  caseName: string;
  examiner: string;
  organization: string;
  evidenceId: string;
  timezone: string;
  classification: string;
  remarks: string;
};

export type BatchHashRow = {
  index?: number;
  name: string;
  size: number;
  lastModified?: string;
  extension?: string;
  signature?: string;
  mime?: string;
  entropy?: number;
  firstBytes?: string;
  risk?: string[];
  md5?: string;
  sha1?: string;
  sha256?: string;
  sha512?: string;
  sha3?: string;
  sm3?: string;
  matched?: boolean;
  matchedAlgorithms?: string[];
  matchedExpectedHashes?: string[];
  matchedExpectedLabels?: string[];
};

export type BatchHashLedgerRow = {
  claim: string;
  scope: string;
  level: string;
  evidence: string;
  result: string;
  action: string;
};

export type PcapSummary = {
  packetCount: number;
  totalCaptured: number;
  firstTimestamp: string;
  lastTimestamp: string;
  topTalkers: Array<[string, number]>;
  topServices: Array<[string, number]>;
  protocols: Array<[string, number]>;
  dnsNames: string[];
  httpHosts: string[];
};

export type PcapPacket = {
  no: number;
  timestamp: string;
  deltaMs: number;
  captured: number;
  original: number;
  protocol: string;
  source: string;
  destination: string;
  sourcePort: number | null;
  destinationPort: number | null;
  flow: string;
  info: string;
  payloadPreview: string;
  hexPreview: string;
  payloadBytes: Uint8Array;
  transportProtocol?: "TCP" | "UDP";
  tcpSequence?: number;
  tcpAcknowledgment?: number;
  tcpFlags?: string;
  tcpPayloadSequence?: number;
  tcpPayloadLength?: number;
  tcpStreamKey?: string;
};

export type PcapTcpStreamSegment = {
  packetNo: number;
  timestamp: string;
  direction: "a-to-b" | "b-to-a";
  sequence: number;
  streamOffset: number;
  gapBefore: number;
  bytes: Uint8Array;
};

export type PcapTcpStream = {
  key: string;
  endpointA: string;
  endpointB: string;
  firstTimestamp: string;
  lastTimestamp: string;
  packetCount: number;
  payloadPacketCount: number;
  bytesAtoB: number;
  bytesBtoA: number;
  retransmittedBytes: number;
  gapBytesAtoB: number;
  gapBytesBtoA: number;
  segments: PcapTcpStreamSegment[];
};

export type PcapConversation = {
  key: string;
  protocol: string;
  endpointA: string;
  endpointB: string;
  packets: number;
  bytes: number;
  firstTimestamp: string;
  lastTimestamp: string;
  risk: string[];
};

export type PcapEndpointStat = {
  endpoint: string;
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  protocols: string[];
  ports: string[];
  firstTimestamp: string;
  lastTimestamp: string;
  risk: string[];
};

export type PcapPortStat = {
  protocol: string;
  port: number;
  packets: number;
  bytes: number;
  endpoints: string[];
  risk: string[];
};

export type PcapTimelineBucket = {
  index: number;
  label: string;
  startTimestamp: string;
  endTimestamp: string;
  packets: number;
  bytes: number;
  protocols: Array<[string, number]>;
  topProtocol: string;
};

export type PcapTimelineEvent = {
  level: string;
  timestamp: string;
  title: string;
  detail: string;
  packetNo?: number;
  flow?: string;
};

export type PcapHttpItem = {
  packetNo: number;
  timestamp: string;
  source: string;
  destination: string;
  host: string;
  line: string;
  method: string;
  path: string;
  userAgent: string;
  contentType: string;
  bodySize: number;
  bodyPreview: string;
  bodySha256: string;
  risk: string[];
};

export type PcapExtractedFile = {
  packetNo: number;
  timestamp: string;
  source: string;
  destination: string;
  host: string;
  path: string;
  contentType: string;
  filename: string;
  size: number;
  sha256: string;
  signature: string;
  preview: string;
  risk: string[];
  bytes: Uint8Array;
};


export type PcapTlsHandshake = {
  streamKey: string;
  direction: "a-to-b" | "b-to-a";
  timestamp: string;
  source: string;
  destination: string;
  type: "ClientHello" | "ServerHello" | "Certificate";
  recordVersion: string;
  negotiatedVersion: string;
  sni: string;
  alpn: string[];
  cipherSuites: string[];
  extensions: string[];
  ja3?: string;
  ja3Hash?: string;
  ja3s?: string;
  ja3sHash?: string;
  certificates: Array<{ size: number; sha256: string }>;
};

export type PcapDnsItem = {
  packetNo: number;
  timestamp: string;
  source: string;
  destination: string;
  name: string;
  type: string;
};

export type YaraStringDef = {
  id: string;
  kind: "text" | "hex" | "regex";
  pattern: string;
  modifiers: string[];
};

export type YaraRuleDef = {
  name: string;
  namespace: string;
  tags: string[];
  meta: Array<[string, string]>;
  strings: YaraStringDef[];
  condition: string;
  errors: string[];
};

export type YaraStringHit = {
  id: string;
  pattern: string;
  count: number;
  offsets: number[];
  preview: string;
  contexts: string[];
};

export type YaraRuleResult = {
  rule: YaraRuleDef;
  matched: boolean;
  score: string;
  hits: YaraStringHit[];
  condition: string;
  errors: string[];
};

export type YaraScanResult = {
  rows: Array<[string, string]>;
  results: YaraRuleResult[];
  findings: Array<{ level: string; title: string; detail: string }>;
  warnings: string[];
};

export type YaraBatchRow = {
  name: string;
  size: number;
  matchedRules: string[];
  matchCount: number;
  stringHits: number;
  warnings: string[];
};

export type TimelineEvent = {
  id: string;
  iso: string;
  local: string;
  raw: string;
  format: string;
  category?: string;
  line: number;
  source: string;
  context: string;
  epochMs?: number;
  risk?: string[];
};

export type FileSignatureDef = {
  bytes: string;
  label: string;
  extensions: string[];
  offset?: number;
};

export type FileEmbeddedSignature = {
  label: string;
  offset: number;
  size: number;
  sha256: string;
  extension: string;
  mime: string;
  preview: string;
  risk: string[];
  confidence?: "low" | "medium" | "high";
  extent?: "exact" | "structural" | "heuristic" | "unknown";
  detail?: string;
  parentOffset?: number;
  depth?: number;
  virtualPath?: string;
  origin?: "signature" | "archive-entry" | "decompressed";
  bytes: Uint8Array;
};

export type FileAnalysis = {
  size: number;
  rows: Array<[string, string]>;
  binaryRows: Array<[string, string]>;
  signatures: Array<{ label: string; signature: string; offset: number; extensions: string[] }>;
  embeddedSignatures: FileEmbeddedSignature[];
  stringAnalysis: StringsAnalysis;
  sideEvidenceScope: string;
  findings: Array<{ level: string; title: string; detail: string }>;
  hexPreview: string;
  asciiPreview: string;
  trailerRows: Array<[string, string]>;
  trailerPreview: string;
  trailerBytes: Uint8Array;
  sections: Array<Record<string, string>>;
};

export type IocRecord = {
  id: string;
  type: string;
  value: string;
  normalized: string;
  line: number;
  lines: number[];
  count: number;
  context: string;
  contexts: string[];
  defanged: string;
  risk: string[];
};

export type IocAnalysis = {
  rows: Array<[string, string]>;
  records: IocRecord[];
  findings: Array<{ level: string; title: string; detail: string }>;
  grouped: Record<string, number>;
};

export type IocEvidenceRow = {
  area: string;
  count: string;
  level: string;
  evidence: string;
  risk: string;
  action: string;
};

export type QrAnalysis = {
  name: string;
  size: number;
  type: string;
  width: number;
  height: number;
  previewUrl: string;
  payload: string;
  payloadType: string;
  payloadRefanged: string;
  payloadDefanged: string;
  payloadHex: string;
  payloadBase64: string;
  decodedBytes: number;
  imageEntropy: number;
  rows: Array<[string, string]>;
  cornerRows: Array<[string, string]>;
  geometryRows: Array<[string, string]>;
  findings: Array<{ level: string; title: string; detail: string }>;
  iocs: IocRecord[];
  payloadRows: Array<[string, string]>;
  urlRows: Array<[string, string]>;
  urlHostRows: Array<[string, string]>;
  urlPathRows: Array<[string, string]>;
  urlOutputs: Array<[string, string]>;
  urlParams: Array<{ key: string; value: string; decodedKey: string; decodedValue: string; decodedTwice?: string; length?: number; decodeDepth?: string; notes: string[] }>;
  urlFindings: Array<{ level: string; title: string; detail: string }>;
};

export type JsonPathRow = {
  path: string;
  type: string;
  value: string;
  length: number;
  risk: string[];
  raw: unknown;
};

export type JsonDecodedRow = {
  path: string;
  method: string;
  risk: string[];
  preview: string;
};

export type JsonAnalysis = {
  ok: boolean;
  empty?: boolean;
  mode: string;
  value: unknown;
  normalized: string;
  minified: string;
  jsonl: string;
  rows: Array<[string, string]>;
  paths: JsonPathRow[];
  decodedRows: JsonDecodedRow[];
  iocs: IocRecord[];
  timestamps: TimelineEvent[];
  findings: Array<{ level: string; title: string; detail: string }>;
  error?: string;
};

export type RegexMatchRow = {
  order: number;
  index: number;
  end: number;
  line: number;
  length: number;
  value: string;
  detectedType: string;
  risk: string[];
  groups: string;
  namedGroups: string;
  context: string;
};

export type RegexAnalysis = {
  ok: boolean;
  rows: Array<[string, string]>;
  matches: RegexMatchRow[];
  replaced: string;
  findings: Array<{ level: string; title: string; detail: string }>;
  error?: string;
};

export type HttpCookieRow = {
  source: string;
  name: string;
  value: string;
  attributes: string;
  risk: string[];
};

export type HttpParamRow = {
  source: string;
  name: string;
  value: string;
  risk: string[];
};

export type HttpHeaderRow = {
  name: string;
  value: string;
  normalizedName: string;
  category: string;
  risk: string[];
};

export type HttpAnalysis = {
  rows: Array<[string, string]>;
  headers: Array<[string, string]>;
  headerRows: HttpHeaderRow[];
  cookies: HttpCookieRow[];
  params: HttpParamRow[];
  authRows: Array<[string, string]>;
  clientRows: Array<[string, string]>;
  securityRows: Array<[string, string]>;
  iocs: IocRecord[];
  bodyJson: JsonAnalysis | null;
  findings: Array<{ level: string; title: string; detail: string }>;
  body: string;
  bodyPreview: string;
  bodyRows: Array<[string, string]>;
  bodyStrings: ExtractedStringRow[];
  bodyTimestamps: TimelineEvent[];
  report: Record<string, unknown>;
};

export type ExtractedStringRow = {
  id: string;
  offset: number;
  encoding: "ASCII" | "UTF-16LE";
  length: number;
  value: string;
  detectedType: string;
  risk: string[];
};

export type StringsAnalysis = {
  rows: Array<[string, string]>;
  typeRows: Array<[string, string]>;
  items: ExtractedStringRow[];
  iocs: IocRecord[];
  timeline: TimelineEvent[];
  findings: Array<{ level: string; title: string; detail: string }>;
  asciiText: string;
  utf16Text: string;
};

export type WindowsArtifactRecord = {
  id: string;
  kind: string;
  fields: Record<string, string>;
};

export type WindowsArtifactAnalysis = {
  name: string;
  size: number;
  artifactType: string;
  rows: Array<[string, string]>;
  timeline: TimelineEvent[];
  strings: ExtractedStringRow[];
  textPreview: string;
  records?: WindowsArtifactRecord[];
};

export type EntropyBlock = {
  offset: number;
  endOffset: number;
  size: number;
  entropy: number;
  asciiRatio: number;
  zeroRatio: number;
  dominantByte: number;
  dominantRatio: number;
  classification: string;
  level: string;
  note: string;
};

export type EntropyRange = {
  start: number;
  end: number;
  size: number;
  blockCount: number;
  classification: string;
  level: string;
  avgEntropy: number;
  avgAsciiRatio: number;
  avgZeroRatio: number;
  note: string;
};

export type EntropyAnalysis = {
  rows: Array<[string, string]>;
  classRows: Array<[string, string]>;
  blocks: EntropyBlock[];
  ranges: EntropyRange[];
  distribution: Array<{ byte: number; count: number; ratio: number }>;
  findings: Array<{ level: string; title: string; detail: string }>;
};

export type UuidAnalysis = {
  input: string;
  valid: boolean;
  normalized: string;
  rows: Array<[string, string]>;
  findings: Array<{ level: string; title: string; detail: string }>;
  bytes: string;
  guidBytes: string;
  version: string;
  variant: string;
  timestamp: string;
  node: string;
};

export type BaseConvertRow = {
  input: string;
  detectedBase: string;
  decimal: string;
  hex: string;
  binary: string;
  octal: string;
  bytesBE: string;
  bytesLE: string;
  ascii: string;
  signed8: string;
  signed16: string;
  signed32: string;
  interpretation: string;
  evidenceType: string;
  risk: string[];
  error?: string;
};

export type BaseConvertAnalysis = {
  rows: Array<[string, string]>;
  items: BaseConvertRow[];
  findings: Array<{ level: string; title: string; detail: string }>;
};

export type PasswordVerifyRow = {
  candidate: string;
  hashType: string;
  matched: boolean;
  detail: string;
  risk: string[];
};

export type EmailAttachmentRow = {
  filename: string;
  contentType: string;
  size: number;
  extension: string;
  signature: string;
  content: Uint8Array;
};

export type EmailAnalysis = {
  rawSize: number;
  rows: Array<[string, string]>;
  headers: Array<[string, string]>;
  received: string[];
  receivedHops: Array<{ index: number; from: string; by: string; ip: string; date: string; raw: string; risk: string[] }>;
  attachments: EmailAttachmentRow[];
  authAssessments: Array<{ mechanism: string; result: string; domain: string; aligned: string; source: string; verdict: string }>;
  bodyText: string;
  bodyHtml: string;
};

export type SqliteValue = string | number | null | Uint8Array;

export type SqliteTableInfo = {
  name: string;
  type: string;
  sql: string;
  rows: number | null;
  columns: number;
};

export type SqliteObjectInfo = {
  name: string;
  type: string;
  tblName: string;
  rootpage: number | null;
  sql: string;
  risk: string[];
};

export type SqliteIndexInfo = {
  name: string;
  unique: boolean;
  origin: string;
  partial: boolean;
  columns: string[];
};

export type SqliteColumnInfo = {
  name: string;
  type: string;
  notNull: boolean;
  defaultValue: string;
  primaryKey: boolean;
};

export type SqliteDataSet = {
  columns: string[];
  values: SqliteValue[][];
  rowids: Array<number | null>;
  editable: boolean;
  message: string;
  totalRows: number | null;
  truncated?: boolean;
};

export type SqliteCellSelection = {
  rowIndex: number;
  columnIndex: number;
  column: string;
  rowid: number | null;
  value: SqliteValue;
};

export type SqliteChangeLog = {
  id: string;
  at: string;
  action: "cell-update" | "row-update" | "row-insert" | "row-delete" | "sql-execute";
  table: string;
  rowid: number | null;
  column?: string;
  before?: string;
  after?: string;
  detail: string;
};

export type SqliteQueryHistoryEntry = {
  id: string;
  at: string;
  sql: string;
  rows: number;
  columns: number;
  mutating: boolean;
  message: string;
};

export type SqliteQueryTemplate = {
  label: string;
  sql: string;
  detail: string;
  level: string;
};

export type SqliteColumnProfile = {
  column: string;
  type: string;
  nulls: number;
  distinct: number;
  numeric: number;
  text: number;
  blob: number;
  risk: string[];
  sample: string;
};

export type SqliteContentHit = {
  rowIndex: number;
  rowid: number | null;
  column: string;
  type: string;
  value: string;
  risk: string[];
};

export type AndroidComponent = {
  type: string;
  name: string;
  exported: string;
  enabled: string;
  permission: string;
  actions: string[];
  categories: string[];
  data: string[];
  risk: string[];
};

export type AndroidApkEntry = {
  name: string;
  directory: string;
  extension: string;
  size: number;
  signature: string;
  role: string;
  risk: string[];
  preview: string;
};

export type AndroidSigningCertificate = {
  size: number;
  sha256: string;
  subject: string;
  issuer: string;
  serial: string;
  validFrom: string;
  validTo: string;
};

export type AndroidSigningAlgorithm = {
  id: number;
  name: string;
  size: number;
  preview: string;
};

export type AndroidSigningSigner = {
  index: number;
  scheme: "v2" | "v3" | "v3.1";
  minSdk: number | null;
  maxSdk: number | null;
  digests: AndroidSigningAlgorithm[];
  signatures: AndroidSigningAlgorithm[];
  certificates: AndroidSigningCertificate[];
  publicKeySize: number;
  publicKeySha256: string;
  attributes: string[];
  notes: string[];
};

export type AndroidSigningSignerVerification = {
  scheme: "v2" | "v3" | "v3.1";
  signerIndex: number;
  verified: boolean;
  signatureVerified: boolean;
  contentDigestVerified: boolean;
  publicKeyMatchesCertificate: boolean;
  selectedAlgorithmId: number | null;
  selectedAlgorithm: string;
  expectedDigest: string;
  actualDigest: string;
  errors: string[];
  warnings: string[];
};

export type AndroidJarV1Verification = {
  present: boolean;
  verified: boolean;
  signerBase: string;
  manifestEntries: number;
  verifiedEntries: number;
  sfManifestDigestVerified: boolean;
  cmsSignatureVerified: boolean;
  signerCertificateSha256: string;
  errors: string[];
  warnings: string[];
};

export type AndroidSigningVerification = {
  status: "verified" | "failed" | "not-signed" | "not-run";
  verified: boolean;
  checkedSchemes: Array<"v1" | "v2" | "v3" | "v3.1">;
  durationMs: number;
  signerResults: AndroidSigningSignerVerification[];
  jarV1?: AndroidJarV1Verification;
  errors: string[];
  warnings: string[];
};

export type AndroidSigningInfo = {
  present: boolean;
  blockOffset: number | null;
  blockSize: number;
  centralDirectoryOffset: number | null;
  schemes: Array<"v2" | "v3" | "v3.1">;
  signers: AndroidSigningSigner[];
  unknownPairIds: string[];
  warnings: string[];
  verified: boolean;
  verification?: AndroidSigningVerification;
};

export type AndroidManifestInfo = {
  name: string;
  size: number;
  sourceFormat: string;
  packageName: string;
  versionCode: string;
  versionName: string;
  minSdk: string;
  targetSdk: string;
  compileSdk: string;
  appLabel: string;
  appIcon: string;
  appTheme: string;
  debuggable: string;
  allowBackup: string;
  cleartextTraffic: string;
  networkSecurityConfig: string;
  launcherActivity: string;
  permissions: string[];
  permissionRows: Array<{
    permission: string;
    shortName: string;
    labelZh: string;
    labelEn: string;
    descZh: string;
    descEn: string;
    category: string;
    categoryKey: string;
    categoryZh: string;
    categoryEn: string;
    severity: string;
    known: boolean;
    risk: string[];
  }>;
  features: string[];
  libraries: string[];
  queries: string[];
  componentRows: Array<[string, string]>;
  axmlRows: Array<[string, string]>;
  components: AndroidComponent[];
  apkRows: Array<[string, string]>;
  apkEntries: AndroidApkEntry[];
  signing?: AndroidSigningInfo;
  findings: Array<{ level: string; title: string; detail: string }>;
};
