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

// Android permission catalog: maps a permission constant to a human-readable
// bilingual label, a plain-language description, a category and a severity so
// the AndroidManifest tool can present permissions from a user's perspective
// (Chinese names, grouped by category, risk highlighted) instead of raw strings.

export type PermSeverity = "dangerous" | "special" | "signature" | "normal" | "unknown";

export type PermCategory =
  | "sms"
  | "contacts"
  | "location"
  | "camera"
  | "microphone"
  | "phone"
  | "calllog"
  | "storage"
  | "media"
  | "calendar"
  | "sensors"
  | "network"
  | "wifi"
  | "bluetooth"
  | "nfc"
  | "accounts"
  | "notification"
  | "background"
  | "special"
  | "system"
  | "other";

export type PermCategoryMeta = { zh: string; en: string; order: number };

// Category metadata. `order` controls display grouping priority (dangerous,
// privacy-sensitive categories first; low-risk/system categories last).
export const PERM_CATEGORY_META: Record<PermCategory, PermCategoryMeta> = {
  sms: { zh: "短信 / 彩信", en: "SMS / MMS", order: 1 },
  contacts: { zh: "通讯录", en: "Contacts", order: 2 },
  calllog: { zh: "通话记录", en: "Call log", order: 3 },
  phone: { zh: "电话与设备标识", en: "Phone & device identity", order: 4 },
  location: { zh: "位置", en: "Location", order: 5 },
  camera: { zh: "相机", en: "Camera", order: 6 },
  microphone: { zh: "麦克风 / 录音", en: "Microphone", order: 7 },
  sensors: { zh: "身体传感器", en: "Body sensors", order: 8 },
  calendar: { zh: "日历", en: "Calendar", order: 9 },
  storage: { zh: "存储", en: "Storage", order: 10 },
  media: { zh: "媒体文件", en: "Media files", order: 11 },
  accounts: { zh: "账户", en: "Accounts", order: 12 },
  special: { zh: "特殊 / 高危权限", en: "Special access", order: 13 },
  notification: { zh: "通知", en: "Notifications", order: 14 },
  background: { zh: "后台运行", en: "Background execution", order: 15 },
  network: { zh: "网络", en: "Network", order: 16 },
  wifi: { zh: "Wi-Fi", en: "Wi-Fi", order: 17 },
  bluetooth: { zh: "蓝牙", en: "Bluetooth", order: 18 },
  nfc: { zh: "NFC", en: "NFC", order: 19 },
  system: { zh: "系统", en: "System", order: 20 },
  other: { zh: "其他", en: "Other", order: 99 }
};

export const PERM_SEVERITY_META: Record<PermSeverity, { zh: string; en: string; order: number }> = {
  dangerous: { zh: "危险", en: "Dangerous", order: 1 },
  special: { zh: "特殊授权", en: "Special", order: 2 },
  signature: { zh: "系统签名", en: "Signature", order: 3 },
  normal: { zh: "普通", en: "Normal", order: 4 },
  unknown: { zh: "未知", en: "Unknown", order: 5 }
};

export type PermInfo = {
  category: PermCategory;
  severity: PermSeverity;
  zh: string;
  en: string;
  descZh: string;
  descEn: string;
};

// Keyed by short name (constant without the `android.permission.` prefix).
export const ANDROID_PERMISSIONS: Record<string, PermInfo> = {
  // --- SMS / MMS ---
  READ_SMS: { category: "sms", severity: "dangerous", zh: "读取短信", en: "Read SMS", descZh: "读取设备上的短信内容，可能获取验证码、隐私对话。", descEn: "Read SMS messages stored on the device, including one-time codes." },
  SEND_SMS: { category: "sms", severity: "dangerous", zh: "发送短信", en: "Send SMS", descZh: "代替用户发送短信，可能产生资费或用于扣费欺诈。", descEn: "Send SMS on the user's behalf; may incur charges or fraud." },
  RECEIVE_SMS: { category: "sms", severity: "dangerous", zh: "接收短信", en: "Receive SMS", descZh: "监听并接收新到短信，常被用于窃取验证码。", descEn: "Intercept incoming SMS; often abused to steal OTP codes." },
  RECEIVE_MMS: { category: "sms", severity: "dangerous", zh: "接收彩信", en: "Receive MMS", descZh: "监听并接收彩信消息。", descEn: "Monitor and receive incoming MMS messages." },
  READ_MMS: { category: "sms", severity: "dangerous", zh: "读取彩信", en: "Read MMS", descZh: "读取设备上的彩信内容。", descEn: "Read MMS content stored on the device." },
  RECEIVE_WAP_PUSH: { category: "sms", severity: "dangerous", zh: "接收 WAP Push", en: "Receive WAP push", descZh: "接收运营商 WAP Push 消息。", descEn: "Receive carrier WAP push messages." },

  // --- Contacts / Accounts ---
  READ_CONTACTS: { category: "contacts", severity: "dangerous", zh: "读取通讯录", en: "Read contacts", descZh: "读取通讯录中的联系人姓名、电话、邮箱等。", descEn: "Read the address book (names, numbers, emails)." },
  WRITE_CONTACTS: { category: "contacts", severity: "dangerous", zh: "修改通讯录", en: "Write contacts", descZh: "新增、修改或删除通讯录联系人。", descEn: "Add, modify or delete contacts." },
  GET_ACCOUNTS: { category: "accounts", severity: "dangerous", zh: "读取账户列表", en: "Get accounts", descZh: "获取设备上已登录的账户（如 Google、邮箱账户）。", descEn: "List accounts registered on the device." },
  MANAGE_ACCOUNTS: { category: "accounts", severity: "normal", zh: "管理账户", en: "Manage accounts", descZh: "添加或移除账户管理器中的账户。", descEn: "Add or remove accounts via AccountManager." },
  AUTHENTICATE_ACCOUNTS: { category: "accounts", severity: "normal", zh: "作为账户验证方", en: "Authenticate accounts", descZh: "充当账户验证器，管理账户凭据。", descEn: "Act as an account authenticator." },
  USE_CREDENTIALS: { category: "accounts", severity: "normal", zh: "使用账户凭据", en: "Use credentials", descZh: "请求账户验证令牌。", descEn: "Request auth tokens from AccountManager." },

  // --- Call log ---
  READ_CALL_LOG: { category: "calllog", severity: "dangerous", zh: "读取通话记录", en: "Read call log", descZh: "读取呼入呼出的通话历史记录。", descEn: "Read the phone call history." },
  WRITE_CALL_LOG: { category: "calllog", severity: "dangerous", zh: "修改通话记录", en: "Write call log", descZh: "新增或删除通话记录条目。", descEn: "Add or delete entries in the call log." },
  PROCESS_OUTGOING_CALLS: { category: "calllog", severity: "dangerous", zh: "监控外拨电话", en: "Process outgoing calls", descZh: "监控并可重定向用户拨出的电话（已弃用）。", descEn: "Observe/redirect outgoing calls (deprecated)." },

  // --- Phone / device identity ---
  READ_PHONE_STATE: { category: "phone", severity: "dangerous", zh: "读取手机状态", en: "Read phone state", descZh: "读取通话状态、运营商、IMEI 等设备标识信息。", descEn: "Read phone/network state and device identifiers." },
  READ_PHONE_NUMBERS: { category: "phone", severity: "dangerous", zh: "读取本机号码", en: "Read phone numbers", descZh: "读取设备的手机号码。", descEn: "Read the device's own phone number(s)." },
  CALL_PHONE: { category: "phone", severity: "dangerous", zh: "直接拨打电话", en: "Call phone", descZh: "无需用户确认直接拨打电话，可能产生资费。", descEn: "Place calls without the dialer UI; may incur charges." },
  ANSWER_PHONE_CALLS: { category: "phone", severity: "dangerous", zh: "接听来电", en: "Answer phone calls", descZh: "以编程方式接听来电。", descEn: "Answer incoming calls programmatically." },
  ADD_VOICEMAIL: { category: "phone", severity: "dangerous", zh: "添加语音信箱", en: "Add voicemail", descZh: "向系统添加语音留言。", descEn: "Add voicemails into the system." },
  USE_SIP: { category: "phone", severity: "dangerous", zh: "使用 SIP 通话", en: "Use SIP", descZh: "使用 SIP 网络电话服务。", descEn: "Make/receive SIP internet calls." },
  READ_PRIVILEGED_PHONE_STATE: { category: "phone", severity: "signature", zh: "读取特权手机状态", en: "Read privileged phone state", descZh: "读取受保护的设备标识（系统/签名级）。", descEn: "Read privileged device identifiers (system app)." },
  MODIFY_PHONE_STATE: { category: "phone", severity: "signature", zh: "修改手机状态", en: "Modify phone state", descZh: "控制电话功能（系统/签名级）。", descEn: "Control telephony features (system app)." },

  // --- Location ---
  ACCESS_FINE_LOCATION: { category: "location", severity: "dangerous", zh: "精确位置", en: "Fine location", descZh: "通过 GPS 获取精确位置（米级）。", descEn: "Access precise (GPS) location." },
  ACCESS_COARSE_LOCATION: { category: "location", severity: "dangerous", zh: "粗略位置", en: "Coarse location", descZh: "通过基站/Wi-Fi 获取大致位置。", descEn: "Access approximate (network) location." },
  ACCESS_BACKGROUND_LOCATION: { category: "location", severity: "dangerous", zh: "后台位置", en: "Background location", descZh: "应用在后台时仍持续获取位置，隐私风险高。", descEn: "Access location while running in the background." },
  ACCESS_MEDIA_LOCATION: { category: "location", severity: "dangerous", zh: "读取媒体地理位置", en: "Media location", descZh: "读取照片/视频中的 EXIF 地理位置信息。", descEn: "Read geolocation metadata (EXIF) from media." },

  // --- Camera / Microphone / Sensors ---
  CAMERA: { category: "camera", severity: "dangerous", zh: "使用相机", en: "Camera", descZh: "拍照、录像，可访问摄像头。", descEn: "Take pictures and record video." },
  RECORD_AUDIO: { category: "microphone", severity: "dangerous", zh: "录音", en: "Record audio", descZh: "使用麦克风录制音频，可能窃听。", descEn: "Record audio via the microphone." },
  BODY_SENSORS: { category: "sensors", severity: "dangerous", zh: "身体传感器", en: "Body sensors", descZh: "访问心率等身体传感器数据。", descEn: "Access body sensor data (e.g. heart rate)." },
  BODY_SENSORS_BACKGROUND: { category: "sensors", severity: "dangerous", zh: "后台身体传感器", en: "Body sensors (background)", descZh: "后台访问身体传感器数据。", descEn: "Access body sensors in the background." },
  ACTIVITY_RECOGNITION: { category: "sensors", severity: "dangerous", zh: "活动识别", en: "Activity recognition", descZh: "识别用户的运动状态（走路、跑步、骑车等）。", descEn: "Detect the user's physical activity." },
  HIGH_SAMPLING_RATE_SENSORS: { category: "sensors", severity: "normal", zh: "高采样率传感器", en: "High-rate sensors", descZh: "以高频率采集运动传感器数据。", descEn: "Sample motion sensors above 200 Hz." },

  // --- Calendar ---
  READ_CALENDAR: { category: "calendar", severity: "dangerous", zh: "读取日历", en: "Read calendar", descZh: "读取日历事件与安排。", descEn: "Read calendar events." },
  WRITE_CALENDAR: { category: "calendar", severity: "dangerous", zh: "修改日历", en: "Write calendar", descZh: "新增、修改或删除日历事件。", descEn: "Add, modify or delete calendar events." },

  // --- Storage / Media ---
  READ_EXTERNAL_STORAGE: { category: "storage", severity: "dangerous", zh: "读取外部存储", en: "Read external storage", descZh: "读取 SD 卡/共享存储中的文件（Android 12 及以下）。", descEn: "Read files from shared/external storage." },
  WRITE_EXTERNAL_STORAGE: { category: "storage", severity: "dangerous", zh: "写入外部存储", en: "Write external storage", descZh: "向共享存储写入文件（Android 12 及以下）。", descEn: "Write files to shared/external storage." },
  MANAGE_EXTERNAL_STORAGE: { category: "special", severity: "special", zh: "管理所有文件", en: "Manage all files", descZh: "访问设备上几乎所有文件，权限极大，需用户在设置中手动授予。", descEn: "Broad access to nearly all files (All files access)." },
  READ_MEDIA_IMAGES: { category: "media", severity: "dangerous", zh: "读取图片", en: "Read images", descZh: "读取相册中的图片文件（Android 13+）。", descEn: "Read image files from shared storage." },
  READ_MEDIA_VIDEO: { category: "media", severity: "dangerous", zh: "读取视频", en: "Read video", descZh: "读取视频文件（Android 13+）。", descEn: "Read video files from shared storage." },
  READ_MEDIA_AUDIO: { category: "media", severity: "dangerous", zh: "读取音频", en: "Read audio", descZh: "读取音频文件（Android 13+）。", descEn: "Read audio files from shared storage." },
  READ_MEDIA_VISUAL_USER_SELECTED: { category: "media", severity: "dangerous", zh: "读取用户选定媒体", en: "User-selected media", descZh: "仅读取用户在选择器中挑选的媒体（Android 14+）。", descEn: "Access only user-selected photos/videos." },
  ACCESS_MEDIA_MANAGEMENT: { category: "media", severity: "special", zh: "媒体管理", en: "Media management", descZh: "批量管理媒体文件，无需逐一确认。", descEn: "Manage media files without per-item consent." },

  // --- Notification ---
  POST_NOTIFICATIONS: { category: "notification", severity: "dangerous", zh: "发送通知", en: "Post notifications", descZh: "向用户发送通知（Android 13+ 需申请）。", descEn: "Show notifications to the user (Android 13+)." },
  ACCESS_NOTIFICATION_POLICY: { category: "notification", severity: "normal", zh: "勿扰模式控制", en: "Notification policy", descZh: "读取或修改勿扰（免打扰）策略。", descEn: "Read/modify Do Not Disturb policy." },
  BIND_NOTIFICATION_LISTENER_SERVICE: { category: "special", severity: "signature", zh: "通知监听服务", en: "Notification listener", descZh: "读取所有应用的通知内容，隐私风险极高。", descEn: "Read notifications from all apps (high risk)." },

  // --- Special / high-risk access ---
  SYSTEM_ALERT_WINDOW: { category: "special", severity: "special", zh: "悬浮窗", en: "Draw over apps", descZh: "在其他应用上方绘制悬浮窗，常被用于覆盖攻击/钓鱼。", descEn: "Draw overlays over other apps (overlay attacks)." },
  WRITE_SETTINGS: { category: "special", severity: "special", zh: "修改系统设置", en: "Write settings", descZh: "修改系统设置项，需用户手动授予。", descEn: "Modify system settings (user must grant)." },
  REQUEST_INSTALL_PACKAGES: { category: "special", severity: "special", zh: "安装应用", en: "Install packages", descZh: "请求安装其他 APK，可能用于静默/诱导安装。", descEn: "Request installation of other APKs." },
  REQUEST_DELETE_PACKAGES: { category: "special", severity: "normal", zh: "卸载应用", en: "Delete packages", descZh: "请求卸载其他应用。", descEn: "Request uninstall of other apps." },
  PACKAGE_USAGE_STATS: { category: "special", severity: "special", zh: "读取应用使用记录", en: "Usage stats", descZh: "读取其他应用的使用时长和频率。", descEn: "Read other apps' usage statistics." },
  BIND_ACCESSIBILITY_SERVICE: { category: "special", severity: "signature", zh: "无障碍服务", en: "Accessibility service", descZh: "可读取屏幕内容、模拟点击，权限极大，恶意软件高频滥用。", descEn: "Read screen & simulate input (heavily abused)." },
  BIND_DEVICE_ADMIN: { category: "special", severity: "signature", zh: "设备管理员", en: "Device admin", descZh: "获取设备管理员权限，可锁屏、清除数据。", descEn: "Device administrator (lock/wipe device)." },
  QUERY_ALL_PACKAGES: { category: "special", severity: "normal", zh: "查询所有应用", en: "Query all packages", descZh: "获取设备上安装的全部应用列表。", descEn: "Enumerate all installed apps (Android 11+)." },
  REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: { category: "background", severity: "normal", zh: "忽略电池优化", en: "Ignore battery optimizations", descZh: "请求不受省电限制，长期后台运行。", descEn: "Run unrestricted in the background." },
  SCHEDULE_EXACT_ALARM: { category: "background", severity: "normal", zh: "精确闹钟", en: "Exact alarm", descZh: "设置精确定时任务，用于后台唤醒。", descEn: "Schedule exact alarms (background wakeups)." },
  USE_EXACT_ALARM: { category: "background", severity: "normal", zh: "使用精确闹钟", en: "Use exact alarm", descZh: "闹钟/日历类应用使用精确定时。", descEn: "Use exact alarms (alarm/calendar apps)." },
  SYSTEM_ALERT_WINDOW_HIDDEN: { category: "special", severity: "special", zh: "隐藏悬浮窗", en: "Hidden overlay", descZh: "在其他应用上方绘制窗口。", descEn: "Overlay window over other apps." },
  BIND_VPN_SERVICE: { category: "special", severity: "normal", zh: "VPN 服务", en: "VPN service", descZh: "创建 VPN，可拦截全部网络流量。", descEn: "Create a VPN and intercept all traffic." },
  BIND_INPUT_METHOD: { category: "special", severity: "signature", zh: "输入法服务", en: "Input method", descZh: "作为输入法，可捕获所有键入内容。", descEn: "Act as an IME (can log keystrokes)." },

  // --- Background / foreground services ---
  FOREGROUND_SERVICE: { category: "background", severity: "normal", zh: "前台服务", en: "Foreground service", descZh: "运行带持久通知的前台服务。", descEn: "Run a foreground service." },
  FOREGROUND_SERVICE_LOCATION: { category: "background", severity: "normal", zh: "前台服务(位置)", en: "Foreground service: location", descZh: "在前台服务中使用位置。", descEn: "Foreground service that uses location." },
  FOREGROUND_SERVICE_CAMERA: { category: "background", severity: "normal", zh: "前台服务(相机)", en: "Foreground service: camera", descZh: "在前台服务中使用相机。", descEn: "Foreground service that uses the camera." },
  FOREGROUND_SERVICE_MICROPHONE: { category: "background", severity: "normal", zh: "前台服务(麦克风)", en: "Foreground service: microphone", descZh: "在前台服务中使用麦克风。", descEn: "Foreground service that uses the mic." },
  RECEIVE_BOOT_COMPLETED: { category: "background", severity: "normal", zh: "开机自启", en: "Boot completed", descZh: "设备开机后自动启动，实现常驻。", descEn: "Auto-start on device boot." },
  WAKE_LOCK: { category: "background", severity: "normal", zh: "保持唤醒", en: "Wake lock", descZh: "阻止 CPU/屏幕休眠。", descEn: "Keep the CPU/screen awake." },
  DISABLE_KEYGUARD: { category: "background", severity: "normal", zh: "禁用锁屏", en: "Disable keyguard", descZh: "临时关闭键盘锁/锁屏。", descEn: "Dismiss the keyguard/lock screen." },
  REORDER_TASKS: { category: "background", severity: "normal", zh: "调整任务顺序", en: "Reorder tasks", descZh: "调整最近任务栈的顺序。", descEn: "Reorder the recent tasks stack." },

  // --- Network / connectivity ---
  INTERNET: { category: "network", severity: "normal", zh: "访问网络", en: "Internet", descZh: "打开网络套接字，进行联网通信。", descEn: "Open network sockets (full internet access)." },
  ACCESS_NETWORK_STATE: { category: "network", severity: "normal", zh: "查看网络状态", en: "Network state", descZh: "查看当前网络连接状态。", descEn: "View network connectivity state." },
  CHANGE_NETWORK_STATE: { category: "network", severity: "normal", zh: "更改网络状态", en: "Change network state", descZh: "更改网络连接性配置。", descEn: "Change network connectivity." },
  ACCESS_WIFI_STATE: { category: "wifi", severity: "normal", zh: "查看 Wi-Fi 状态", en: "Wi-Fi state", descZh: "查看 Wi-Fi 连接信息。", descEn: "View Wi-Fi connection info." },
  CHANGE_WIFI_STATE: { category: "wifi", severity: "normal", zh: "更改 Wi-Fi 状态", en: "Change Wi-Fi state", descZh: "开关 Wi-Fi、切换连接。", descEn: "Connect/disconnect Wi-Fi." },
  CHANGE_WIFI_MULTICAST_STATE: { category: "wifi", severity: "normal", zh: "Wi-Fi 组播", en: "Wi-Fi multicast", descZh: "接收 Wi-Fi 组播报文。", descEn: "Receive Wi-Fi multicast packets." },
  NEARBY_WIFI_DEVICES: { category: "wifi", severity: "dangerous", zh: "附近 Wi-Fi 设备", en: "Nearby Wi-Fi devices", descZh: "扫描并连接附近 Wi-Fi 设备（Android 13+）。", descEn: "Discover nearby Wi-Fi devices." },
  BLUETOOTH: { category: "bluetooth", severity: "normal", zh: "蓝牙", en: "Bluetooth", descZh: "连接已配对的蓝牙设备（Android 11 及以下）。", descEn: "Connect to paired Bluetooth devices." },
  BLUETOOTH_ADMIN: { category: "bluetooth", severity: "normal", zh: "蓝牙管理", en: "Bluetooth admin", descZh: "发现并配对蓝牙设备。", descEn: "Discover and pair Bluetooth devices." },
  BLUETOOTH_CONNECT: { category: "bluetooth", severity: "dangerous", zh: "连接蓝牙设备", en: "Bluetooth connect", descZh: "连接已配对蓝牙设备（Android 12+）。", descEn: "Connect to paired devices (Android 12+)." },
  BLUETOOTH_SCAN: { category: "bluetooth", severity: "dangerous", zh: "扫描蓝牙设备", en: "Bluetooth scan", descZh: "扫描附近蓝牙设备（Android 12+）。", descEn: "Scan for nearby Bluetooth devices." },
  BLUETOOTH_ADVERTISE: { category: "bluetooth", severity: "dangerous", zh: "蓝牙广播", en: "Bluetooth advertise", descZh: "向附近设备广播蓝牙信号。", descEn: "Advertise to nearby Bluetooth devices." },
  NFC: { category: "nfc", severity: "normal", zh: "NFC", en: "NFC", descZh: "进行近场通信（刷卡、标签读取）。", descEn: "Perform NFC operations." },

  // --- System ---
  VIBRATE: { category: "system", severity: "normal", zh: "振动", en: "Vibrate", descZh: "控制设备振动器。", descEn: "Control the vibrator." },
  FLASHLIGHT: { category: "system", severity: "normal", zh: "闪光灯", en: "Flashlight", descZh: "控制闪光灯。", descEn: "Control the flashlight." },
  SET_WALLPAPER: { category: "system", severity: "normal", zh: "设置壁纸", en: "Set wallpaper", descZh: "更换系统壁纸。", descEn: "Change the wallpaper." },
  EXPAND_STATUS_BAR: { category: "system", severity: "normal", zh: "展开状态栏", en: "Expand status bar", descZh: "展开或折叠通知栏。", descEn: "Expand/collapse the status bar." },
  MODIFY_AUDIO_SETTINGS: { category: "system", severity: "normal", zh: "修改音频设置", en: "Modify audio settings", descZh: "修改全局音量等音频设置。", descEn: "Modify global audio settings." },
  READ_SYNC_SETTINGS: { category: "system", severity: "normal", zh: "读取同步设置", en: "Read sync settings", descZh: "读取账户同步设置。", descEn: "Read sync settings." },
  WRITE_SYNC_SETTINGS: { category: "system", severity: "normal", zh: "修改同步设置", en: "Write sync settings", descZh: "修改账户同步设置。", descEn: "Modify sync settings." },
  RECEIVE_USER_PRESENT: { category: "system", severity: "normal", zh: "监听解锁", en: "User present", descZh: "监听用户解锁屏幕事件。", descEn: "Detect when the user unlocks the device." },
  GET_TASKS: { category: "system", severity: "normal", zh: "读取运行任务", en: "Get tasks", descZh: "读取当前/最近运行的任务（已弃用）。", descEn: "Read running/recent tasks (deprecated)." },
  KILL_BACKGROUND_PROCESSES: { category: "system", severity: "normal", zh: "结束后台进程", en: "Kill background processes", descZh: "结束其他应用的后台进程。", descEn: "Kill other apps' background processes." },
  USE_FINGERPRINT: { category: "system", severity: "normal", zh: "指纹识别", en: "Use fingerprint", descZh: "使用指纹进行身份验证（已弃用）。", descEn: "Use fingerprint auth (deprecated)." },
  USE_BIOMETRIC: { category: "system", severity: "normal", zh: "生物识别", en: "Use biometric", descZh: "使用指纹/人脸等生物特征验证。", descEn: "Use biometric authentication." },
  READ_LOGS: { category: "special", severity: "signature", zh: "读取系统日志", en: "Read logs", descZh: "读取系统日志，可能包含其他应用的敏感信息。", descEn: "Read system logs (may leak other apps' data)." },
  DUMP: { category: "special", severity: "signature", zh: "读取系统诊断", en: "Dump", descZh: "获取系统服务的诊断信息。", descEn: "Retrieve system diagnostic dumps." },
  WRITE_SECURE_SETTINGS: { category: "special", severity: "signature", zh: "修改安全设置", en: "Write secure settings", descZh: "修改系统安全设置（系统/签名级）。", descEn: "Modify secure system settings (system app)." },
  INSTALL_PACKAGES: { category: "special", severity: "signature", zh: "静默安装应用", en: "Install packages (silent)", descZh: "无提示安装应用（系统/签名级）。", descEn: "Silently install packages (system app)." },
  DELETE_PACKAGES: { category: "special", severity: "signature", zh: "静默卸载应用", en: "Delete packages (silent)", descZh: "无提示卸载应用（系统/签名级）。", descEn: "Silently delete packages (system app)." },
  MOUNT_UNMOUNT_FILESYSTEMS: { category: "special", severity: "signature", zh: "挂载文件系统", en: "Mount filesystems", descZh: "挂载/卸载外部存储（系统/签名级）。", descEn: "Mount/unmount filesystems (system app)." }
};

// Categorise a permission string using the catalog, falling back to
// regex-based heuristics for constants that are not explicitly listed.
export function resolveAndroidPermission(permission: string): {
  shortName: string;
  info: PermInfo;
  known: boolean;
} {
  const isAndroid = permission.startsWith("android.permission.");
  const shortName = permission.includes(".") ? permission.slice(permission.lastIndexOf(".") + 1) : permission;
  const direct = ANDROID_PERMISSIONS[shortName];
  if (direct && isAndroid) {
    return { shortName, info: direct, known: true };
  }
  // Google Play services / vendor permissions and unknown android.* fall back to heuristics.
  const info = heuristicPermission(permission, shortName, isAndroid);
  return { shortName, info, known: false };
}

const HEURISTIC_PATTERNS: Array<[RegExp, PermCategory, PermSeverity]> = [
  [/SMS|MMS|WAP_PUSH/i, "sms", "dangerous"],
  [/CONTACT/i, "contacts", "dangerous"],
  [/CALL_LOG/i, "calllog", "dangerous"],
  [/PHONE|TELEPHON|SIP|VOICEMAIL/i, "phone", "dangerous"],
  [/LOCATION|GPS/i, "location", "dangerous"],
  [/CAMERA/i, "camera", "dangerous"],
  [/AUDIO_RECORD|RECORD_AUDIO|MICROPHONE/i, "microphone", "dangerous"],
  [/SENSOR|ACTIVITY_RECOGNITION|BODY/i, "sensors", "dangerous"],
  [/CALENDAR/i, "calendar", "dangerous"],
  [/MEDIA_IMAGE|MEDIA_VIDEO|MEDIA_AUDIO|READ_MEDIA/i, "media", "dangerous"],
  [/STORAGE|EXTERNAL_STORAGE/i, "storage", "dangerous"],
  [/ACCOUNT|CREDENTIAL/i, "accounts", "normal"],
  [/NOTIFICATION/i, "notification", "normal"],
  [/ACCESSIBILITY|DEVICE_ADMIN|SYSTEM_ALERT|OVERLAY|WRITE_SETTINGS|INSTALL_PACKAGES|USAGE_STATS|MANAGE_EXTERNAL|VPN|INPUT_METHOD/i, "special", "special"],
  [/FOREGROUND_SERVICE|BOOT_COMPLETED|WAKE_LOCK|ALARM|BATTERY/i, "background", "normal"],
  [/BLUETOOTH/i, "bluetooth", "dangerous"],
  [/WIFI/i, "wifi", "normal"],
  [/\bNFC\b/i, "nfc", "normal"],
  [/INTERNET|NETWORK/i, "network", "normal"]
];

function humanizeShortName(shortName: string): string {
  return shortName
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function heuristicPermission(permission: string, shortName: string, isAndroid: boolean): PermInfo {
  const matched = HEURISTIC_PATTERNS.find(([pattern]) => pattern.test(permission));
  const category: PermCategory = matched?.[1] ?? "other";
  const severity: PermSeverity = matched?.[2] ?? (isAndroid ? "normal" : "unknown");
  const human = humanizeShortName(shortName);
  const zh = isAndroid ? `系统权限：${human}` : `自定义权限：${human}`;
  const en = isAndroid ? human : `Custom: ${human}`;
  const descZh = isAndroid
    ? "标准 Android 权限（未在词典中，按名称归类）。"
    : "由应用或第三方 SDK 声明的自定义权限，需结合上下文判断。";
  const descEn = isAndroid
    ? "Standard Android permission (not catalogued; categorised by name)."
    : "Custom permission declared by the app or a third-party SDK.";
  return { category, severity, zh, en, descZh, descEn };
}
