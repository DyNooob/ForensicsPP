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

/**
 * EXIF / metadata field and value localization.
 *
 * The metadata parser (exifr) emits canonical English/ASCII tags such as
 * `Make`, `Model`, `GPSLatitude`. Forensic examiners still want the canonical
 * tag name as a reference, but the *field label* should read in the UI locale.
 * Proper nouns and conventional acronyms (EXIF, GPS, ISO, ICC, XMP, IPTC, DPI,
 * RGB, sRGB, Adobe RGB, WGS-84, ...) are intentionally preserved.
 */

type Localized = { zh: string; en: string };

/**
 * Numeric EXIF/TIFF/GPS tag ID -> canonical (English) tag name.
 *
 * exifr returns the *curated* default tags with their named keys (Make, Model,
 * GPSLatitude, ...) but returns the rest of the Exif IFD block with raw numeric
 * tag IDs (e.g. 33434, 34850, 41986). Resolve those to canonical names so the
 * localized labels and enum values below can be applied uniformly.
 */
export const EXIF_TAG_NAMES: Record<number, string> = {
  254: "NewSubfileType", 255: "SubfileType", 256: "ImageWidth", 257: "ImageHeight",
  258: "BitsPerSample", 259: "Compression", 262: "PhotometricInterpretation",
  263: "Threshholding", 266: "FillOrder", 269: "DocumentName", 270: "ImageDescription",
  271: "Make", 272: "Model", 273: "StripOffsets", 274: "Orientation",
  277: "SamplesPerPixel", 278: "RowsPerStrip", 279: "StripByteCounts",
  282: "XResolution", 283: "YResolution", 284: "PlanarConfiguration",
  290: "GrayResponseUnit", 291: "GrayResponse", 296: "ResolutionUnit",
  301: "TransferFunction", 305: "Software", 306: "DateTime", 315: "Artist",
  316: "HostComputer", 318: "WhitePoint", 319: "PrimaryChromaticities",
  321: "YCbCrCoefficients", 322: "YCbCrSubSampling", 323: "YCbCrPositioning",
  324: "ReferenceBlackWhite", 338: "ExtraSamples", 339: "SampleFormat",
  512: "JPEGProc", 513: "JpegInterchangeFormat", 514: "JpegInterchangeFormatLength",
  700: "ColorMap",
  // Exif IFD
  33421: "CFARepeatPatternDim", 33422: "CFAPattern", 33423: "BatteryLevel",
  33432: "Copyright", 33434: "ExposureTime", 33437: "FNumber",
  33445: "InterColorProfile", 34377: "ImageResources",
  34665: "ExifOffset", 34675: "InteropOffset",
  34850: "ExposureProgram", 34852: "SpectralSensitivity", 34855: "ISO",
  34856: "OECF", 34864: "SensitivityType", 34865: "StandardOutputSensitivity",
  34866: "ISOSpeed", 34867: "ISOSpeedLatitudeYYY", 34868: "ISOSpeedLatitudeZZZ",
  36864: "ExifVersion", 36867: "DateTimeOriginal", 36868: "CreateDate",
  36880: "OffsetTime", 36881: "OffsetTimeOriginal", 36882: "OffsetTimeDigitized",
  37121: "ComponentsConfiguration", 37122: "CompressedBitsPerPixel",
  37377: "ShutterSpeedValue", 37378: "ApertureValue", 37379: "BrightnessValue",
  37380: "ExposureBias", 37381: "MaxApertureValue", 37382: "SubjectDistance",
  37383: "LightSource", 37385: "Flash", 37386: "FocalLength",
  37387: "FlashEnergy", 37388: "SpatialFrequencyResponse",
  37390: "FocalPlaneXResolution", 37391: "FocalPlaneYResolution",
  37392: "FocalPlaneResolutionUnit", 37393: "SubjectLocation", 37394: "ExposureIndex",
  37395: "SensingMethod", 37397: "FileSource", 37398: "SceneType",
  37399: "CFAPlaneColor", 37400: "CFALayout",
  37500: "MakerNote", 37510: "UserComment", 37520: "SubSecTime",
  37521: "SubSecTimeOriginal", 37522: "SubSecTimeDigitized",
  40960: "FlashpixVersion", 40961: "ColorSpace", 40962: "ExifImageWidth",
  40963: "ExifImageHeight", 40965: "InteropOffset", 41483: "FlashEnergy",
  41484: "SpatialFrequencyResponse", 41486: "FocalPlaneXResolution",
  41487: "FocalPlaneYResolution", 41488: "FocalPlaneResolutionUnit",
  41492: "SubjectLocation", 41493: "ExposureIndex", 41495: "SensingMethod",
  41728: "RecommendedExposureIndex", 41729: "Interlace", 41730: "TimeZoneOffset",
  41985: "MeteringMode", 41986: "ExposureMode", 41987: "WhiteBalance",
  41988: "DigitalZoomRatio", 41989: "FocalLengthIn35mmFilm",
  41990: "Flash", 41991: "SceneCaptureType", 41992: "Contrast",
  41993: "Saturation", 41994: "Sharpness", 41995: "DeviceSettingDescription",
  41996: "SubjectDistanceRange", 41998: "SceneCaptureType",
  42016: "BodySerialNumber", 42032: "CameraOwnerName", 42033: "CameraSerialNumber",
  42034: "LensSpecification", 42035: "LensMake", 42036: "LensModel",
  42037: "LensSerialNumber", 42080: "ImageUniqueID", 42240: "Gamma",
  // GPS IFD (exifr usually names these, but cover numeric form too)
  0: "GPSVersionID", 1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef",
  4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude", 7: "GPSTimeStamp",
  8: "GPSSatellites", 9: "GPSStatus", 10: "GPSMeasureMode", 11: "GPSDOP",
  12: "GPSSpeedRef", 13: "GPSSpeed", 14: "GPSTrackRef", 15: "GPSTrack",
  16: "GPSImgDirectionRef", 17: "GPSImgDirection", 18: "GPSMapDatum",
  19: "GPSDestLatitudeRef", 20: "GPSDestLatitude", 21: "GPSDestLongitudeRef",
  22: "GPSDestLongitude", 23: "GPSDestBearingRef", 24: "GPSDestBearing",
  25: "GPSDestDistanceRef", 26: "GPSDestDistance", 27: "GPSProcessingMethod",
  28: "GPSAreaInformation", 29: "GPSDateStamp", 30: "GPSDifferential",
  31: "GPSHPositioningError"
};

/** Resolves a numeric exifr tag id to its canonical name; passes names through. */
function resolveTagName(key: string): string {
  if (/^\d+$/.test(key)) {
    const id = Number(key);
    return EXIF_TAG_NAMES[id] ?? key;
  }
  return key;
}

/** Field name -> localized label. `en` keeps the canonical tag for forensic reference. */
export const EXIF_FIELD_LABELS: Record<string, Localized> = {
  // --- TIFF / IFD0 ---
  Make: { zh: "设备厂商", en: "Make" },
  Model: { zh: "设备型号", en: "Model" },
  Software: { zh: "处理软件", en: "Software" },
  Orientation: { zh: "拍摄方向", en: "Orientation" },
  ImageWidth: { zh: "图像宽度", en: "ImageWidth" },
  ImageHeight: { zh: "图像高度", en: "ImageHeight" },
  PixelXDimension: { zh: "像素宽度", en: "PixelXDimension" },
  PixelYDimension: { zh: "像素高度", en: "PixelYDimension" },
  XResolution: { zh: "水平分辨率", en: "XResolution" },
  YResolution: { zh: "垂直分辨率", en: "YResolution" },
  ResolutionUnit: { zh: "分辨率单位", en: "ResolutionUnit" },
  BitsPerSample: { zh: "位深度", en: "BitsPerSample" },
  Compression: { zh: "压缩方式", en: "Compression" },
  PhotometricInterpretation: { zh: "色彩表示", en: "PhotometricInterpretation" },
  SamplesPerPixel: { zh: "像素分量数", en: "SamplesPerPixel" },
  PlanarConfiguration: { zh: "平面配置", en: "PlanarConfiguration" },
  YCbCrPositioning: { zh: "色度定位", en: "YCbCrPositioning" },
  ColorSpace: { zh: "色彩空间", en: "ColorSpace" },
  FlashpixVersion: { zh: "Flashpix 版本", en: "FlashpixVersion" },
  ExifVersion: { zh: "Exif 版本", en: "ExifVersion" },
  InteropVersion: { zh: "互操作版本", en: "InteropVersion" },
  ImageDescription: { zh: "图像描述", en: "ImageDescription" },
  Artist: { zh: "作者", en: "Artist" },
  Copyright: { zh: "版权", en: "Copyright" },
  DocumentName: { zh: "文档名称", en: "DocumentName" },
  DateTime: { zh: "修改时间", en: "DateTime" },
  CreateDate: { zh: "创建时间", en: "CreateDate" },
  ModifyDate: { zh: "修改时间", en: "ModifyDate" },
  OffsetTime: { zh: "时区偏移", en: "OffsetTime" },
  OffsetTimeOriginal: { zh: "拍摄时区偏移", en: "OffsetTimeOriginal" },
  OffsetTimeDigitized: { zh: "数字化时区偏移", en: "OffsetTimeDigitized" },

  // --- Exif IFD ---
  ExposureTime: { zh: "曝光时间", en: "ExposureTime" },
  FNumber: { zh: "光圈值", en: "FNumber" },
  ApertureValue: { zh: "光圈值 (APEX)", en: "ApertureValue" },
  ShutterSpeedValue: { zh: "快门速度 (APEX)", en: "ShutterSpeedValue" },
  BrightnessValue: { zh: "亮度 (APEX)", en: "BrightnessValue" },
  ExposureBias: { zh: "曝光补偿", en: "ExposureBias" },
  MaxApertureValue: { zh: "最大光圈 (APEX)", en: "MaxApertureValue" },
  ExposureProgram: { zh: "曝光程序", en: "ExposureProgram" },
  ISO: { zh: "感光度 (ISO)", en: "ISO" },
  ISOSpeedRatings: { zh: "感光度", en: "ISOSpeedRatings" },
  SensitivityType: { zh: "灵敏度类型", en: "SensitivityType" },
  RecommendedExposureIndex: { zh: "推荐曝光指数", en: "RecommendedExposureIndex" },
  ISOSpeed: { zh: "ISO 速度", en: "ISOSpeed" },
  ExposureMode: { zh: "曝光模式", en: "ExposureMode" },
  WhiteBalance: { zh: "白平衡", en: "WhiteBalance" },
  MeteringMode: { zh: "测光模式", en: "MeteringMode" },
  Flash: { zh: "闪光灯", en: "Flash" },
  FocalLength: { zh: "焦距", en: "FocalLength" },
  FocalLengthIn35mmFilm: { zh: "等效 35mm 焦距", en: "FocalLengthIn35mmFilm" },
  SubjectDistance: { zh: "拍摄距离", en: "SubjectDistance" },
  SceneCaptureType: { zh: "场景类型", en: "SceneCaptureType" },
  Contrast: { zh: "对比度", en: "Contrast" },
  Saturation: { zh: "饱和度", en: "Saturation" },
  Sharpness: { zh: "锐度", en: "Sharpness" },
  DigitalZoomRatio: { zh: "数码变焦倍率", en: "DigitalZoomRatio" },
  GainControl: { zh: "增益控制", en: "GainControl" },
  LightSource: { zh: "光源", en: "LightSource" },
  CustomRendered: { zh: "自定义处理", en: "CustomRendered" },
  SceneType: { zh: "场景主体", en: "SceneType" },
  FileSource: { zh: "文件来源", en: "FileSource" },
  SensingMethod: { zh: "感光方式", en: "SensingMethod" },
  SubjectArea: { zh: "主体区域", en: "SubjectArea" },
  ComponentsConfiguration: { zh: "分量配置", en: "ComponentsConfiguration" },
  CompressedBitsPerPixel: { zh: "压缩比特率", en: "CompressedBitsPerPixel" },
  UserComment: { zh: "用户注释", en: "UserComment" },
  SubSecTime: { zh: "亚秒时间", en: "SubSecTime" },
  SubSecTimeOriginal: { zh: "拍摄亚秒", en: "SubSecTimeOriginal" },
  SubSecTimeDigitized: { zh: "数字化亚秒", en: "SubSecTimeDigitized" },
  DateTimeOriginal: { zh: "拍摄时间", en: "DateTimeOriginal" },
  DateTimeDigitized: { zh: "数字化时间", en: "DateTimeDigitized" },
  DeviceSettingDescription: { zh: "设备设置描述", en: "DeviceSettingDescription" },
  CameraOwnerName: { zh: "相机所有者", en: "CameraOwnerName" },
  BodySerialNumber: { zh: "机身序列号", en: "BodySerialNumber" },
  LensModel: { zh: "镜头型号", en: "LensModel" },
  LensMake: { zh: "镜头厂商", en: "LensMake" },
  LensSerialNumber: { zh: "镜头序列号", en: "LensSerialNumber" },
  ImageUniqueID: { zh: "图像唯一 ID", en: "ImageUniqueID" },
  MakerNote: { zh: "厂商注释", en: "MakerNote" },

  // --- GPS IFD ---
  GPSVersionID: { zh: "GPS 版本", en: "GPSVersionID" },
  GPSLatitudeRef: { zh: "纬度参考 (南北)", en: "GPSLatitudeRef" },
  GPSLatitude: { zh: "拍摄纬度", en: "GPSLatitude" },
  GPSLongitudeRef: { zh: "经度参考 (东西)", en: "GPSLongitudeRef" },
  GPSLongitude: { zh: "拍摄经度", en: "GPSLongitude" },
  GPSAltitudeRef: { zh: "海拔参考", en: "GPSAltitudeRef" },
  GPSAltitude: { zh: "拍摄海拔", en: "GPSAltitude" },
  GPSTimeStamp: { zh: "GPS 时间", en: "GPSTimeStamp" },
  GPSSatellites: { zh: "GPS 卫星", en: "GPSSatellites" },
  GPSStatus: { zh: "GPS 状态", en: "GPSStatus" },
  GPSMeasureMode: { zh: "GPS 测量模式", en: "GPSMeasureMode" },
  GPSDOP: { zh: "GPS 精度 (DOP)", en: "GPSDOP" },
  GPSSpeedRef: { zh: "速度单位", en: "GPSSpeedRef" },
  GPSSpeed: { zh: "GPS 速度", en: "GPSSpeed" },
  GPSTrackRef: { zh: "行进方向参考", en: "GPSTrackRef" },
  GPSTrack: { zh: "行进方向", en: "GPSTrack" },
  GPSImgDirectionRef: { zh: "影像方位参考", en: "GPSImgDirectionRef" },
  GPSImgDirection: { zh: "影像方位", en: "GPSImgDirection" },
  GPSMapDatum: { zh: "地图基准", en: "GPSMapDatum" },
  GPSDestLatitudeRef: { zh: "目的地纬度参考", en: "GPSDestLatitudeRef" },
  GPSDestLatitude: { zh: "目的地纬度", en: "GPSDestLatitude" },
  GPSDestLongitudeRef: { zh: "目的地经度参考", en: "GPSDestLongitudeRef" },
  GPSDestLongitude: { zh: "目的地经度", en: "GPSDestLongitude" },
  GPSDestBearingRef: { zh: "目的地方位参考", en: "GPSDestBearingRef" },
  GPSDestBearing: { zh: "目的地方位", en: "GPSDestBearing" },
  GPSDestDistanceRef: { zh: "目的地距离单位", en: "GPSDestDistanceRef" },
  GPSDestDistance: { zh: "目的地距离", en: "GPSDestDistance" },
  GPSProcessingMethod: { zh: "GPS 处理方法", en: "GPSProcessingMethod" },
  GPSAreaInformation: { zh: "GPS 区域信息", en: "GPSAreaInformation" },
  GPSDateStamp: { zh: "GPS 日期", en: "GPSDateStamp" },
  GPSDifferential: { zh: "GPS 差分校正", en: "GPSDifferential" },
  GPSHPositioningError: { zh: "GPS 水平定位误差", en: "GPSHPositioningError" },

  // --- JFIF ---
  JFIFVersion: { zh: "JFIF 版本", en: "JFIFVersion" },
  ThumbnailWidth: { zh: "缩略图宽度", en: "ThumbnailWidth" },
  ThumbnailHeight: { zh: "缩略图高度", en: "ThumbnailHeight" },

  // --- ICC ---
  ProfileName: { zh: "ICC 配置文件名", en: "ProfileName" },
  ProfileDescription: { zh: "ICC 配置文件描述", en: "ProfileDescription" },
  ProfileCMMType: { zh: "ICC CMM 类型", en: "ProfileCMMType" },
  ProfileVersion: { zh: "ICC 版本", en: "ProfileVersion" },
  ProfileClass: { zh: "ICC 配置文件类别", en: "ProfileClass" },
  ColorSpaceData: { zh: "ICC 色彩空间数据", en: "ColorSpaceData" },
  ProfileConnectionSpace: { zh: "ICC 连接色彩空间", en: "ProfileConnectionSpace" },
  ProfileDateTime: { zh: "ICC 配置文件时间", en: "ProfileDateTime" },
  PrimaryPlatform: { zh: "ICC 主平台", en: "PrimaryPlatform" },
  CMMFlags: { zh: "ICC CMM 标志", en: "CMMFlags" },
  DeviceManufacturer: { zh: "ICC 设备制造商", en: "DeviceManufacturer" },
  DeviceModel: { zh: "ICC 设备型号", en: "DeviceModel" },
  DeviceAttributes: { zh: "ICC 设备属性", en: "DeviceAttributes" },
  RenderingIntent: { zh: "ICC 渲染意图", en: "RenderingIntent" },
  ProfileCreator: { zh: "ICC 配置文件创建者", en: "ProfileCreator" },
  ProfileID: { zh: "ICC 配置文件 ID", en: "ProfileID" },
  ProfileCopyright: { zh: "ICC 版权", en: "ProfileCopyright" },
  ProfileFileSignature: { zh: "ICC 文件签名", en: "ProfileFileSignature" },

  // --- Windows XP / IPTC / XMP common ---
  Title: { zh: "标题", en: "Title" },
  Description: { zh: "描述", en: "Description" },
  Subject: { zh: "主题", en: "Subject" },
  Creator: { zh: "创作者", en: "Creator" },
  Rights: { zh: "版权信息", en: "Rights" },
  DateCreated: { zh: "创建日期", en: "DateCreated" },
  Format: { zh: "格式", en: "Format" },
  Rating: { zh: "评分", en: "Rating" },
  RatingPercent: { zh: "评分 (百分比)", en: "RatingPercent" },
  Keywords: { zh: "关键词", en: "Keywords" },

  // --- exifr computed fields ---
  latitude: { zh: "纬度", en: "latitude" },
  longitude: { zh: "经度", en: "longitude" },
  altitude: { zh: "海拔", en: "altitude" },
  datetime: { zh: "时间", en: "datetime" },
  timestamp: { zh: "时间戳", en: "timestamp" }
};

/**
 * Enum value localization, keyed by field name. Keys accept both numeric
 * (stringified) and lower-cased string forms because exifr returns some
 * enums as numbers and some as descriptive strings.
 */
export const EXIF_VALUE_LABELS: Record<string, Record<string, Localized>> = {
  Orientation: {
    "1": { zh: "正常 (0°)", en: "Normal (0°)" },
    "2": { zh: "水平翻转", en: "Mirrored horizontal" },
    "3": { zh: "旋转 180°", en: "Rotate 180°" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "旋转 90° CW", en: "Rotate 90° CW" },
    "7": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
    "8": { zh: "旋转 270° 顺时针", en: "Rotate 270 CW" },
    "Horizontal (normal)": { zh: "正常 (0°)", en: "Horizontal (normal)" },
    "Mirror horizontal": { zh: "水平翻转", en: "Mirror horizontal" },
    "Rotate 180": { zh: "旋转 180°", en: "Rotate 180" },
    "Mirror vertical": { zh: "垂直翻转", en: "Mirror vertical" },
    "Mirror horizontal and rotate 270 CW": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "Rotate 90 CW": { zh: "旋转 90° 顺时针", en: "Rotate 90 CW" },
    "Mirror horizontal and rotate 90 CW": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
    "Rotate 270 CW": { zh: "旋转 270° 顺时针", en: "Rotate 270 CW" }
  },
  Flash: {
    "flash did not fire": { zh: "未闪光", en: "Flash did not fire" },
    "flash fired": { zh: "已闪光", en: "Flash fired" },
    "no flash": { zh: "无闪光灯", en: "No flash" },
    "flash": { zh: "闪光灯", en: "Flash" },
    "0": { zh: "未闪光", en: "No flash" },
    "1": { zh: "已闪光", en: "Flash fired" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "7": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
    "9": { zh: "未闪光 (强制关闭)", en: "Flash off, forced" },
    "16": { zh: "无闪光灯功能", en: "No flash function" },
    "24": { zh: "不支持闪光灯", en: "Flash not supported" },
    "25": { zh: "已闪光 (自动)", en: "Flash fired, auto" },
    "32": { zh: "未闪光 (自动)", en: "Flash did not fire, auto" }
  },
  ExposureProgram: {
    "0": { zh: "未定义", en: "Not defined" },
    "1": { zh: "手动", en: "Manual" },
    "2": { zh: "程序自动", en: "Program AE" },
    "3": { zh: "光圈优先", en: "Aperture priority" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "运动模式", en: "Action program" },
    "7": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
    "8": { zh: "旋转 270° 顺时针", en: "Rotate 270 CW" },
    "manual": { zh: "手动", en: "Manual" },
    "program": { zh: "程序自动", en: "Program AE" },
    "aperture priority": { zh: "光圈优先", en: "Aperture priority" },
    "shutter priority": { zh: "快门优先", en: "Shutter priority" }
  },
  WhiteBalance: {
    "0": { zh: "自动", en: "Auto" },
    "1": { zh: "手动", en: "Manual" },
    "auto": { zh: "自动", en: "Auto" },
    "manual": { zh: "手动", en: "Manual" }
  },
  MeteringMode: {
    "0": { zh: "未知", en: "Unknown" },
    "1": { zh: "平均测光", en: "Average" },
    "2": { zh: "中央重点平均", en: "Center-weighted average" },
    "3": { zh: "点测光", en: "Spot" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "局部测光", en: "Partial" },
    "255": { zh: "其他", en: "Other" }
  },
  SceneCaptureType: {
    "0": { zh: "标准", en: "Standard" },
    "1": { zh: "风景", en: "Landscape" },
    "2": { zh: "人像", en: "Portrait" },
    "3": { zh: "夜景", en: "Night" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
  },
  Contrast: {
    "0": { zh: "正常", en: "Normal" },
    "1": { zh: "柔和", en: "Soft" },
    "2": { zh: "鲜艳", en: "Hard" }
  },
  Saturation: {
    "0": { zh: "正常", en: "Normal" },
    "1": { zh: "低饱和度", en: "Low" },
    "2": { zh: "高饱和度", en: "High" }
  },
  Sharpness: {
    "0": { zh: "正常", en: "Normal" },
    "1": { zh: "柔和", en: "Soft" },
    "2": { zh: "锐利", en: "Hard" }
  },
  ExposureMode: {
    "0": { zh: "自动", en: "Auto" },
    "1": { zh: "手动", en: "Manual" },
    "2": { zh: "自动包围", en: "Auto bracket" }
  },
  CustomRendered: {
    "0": { zh: "正常", en: "Normal" },
    "1": { zh: "自定义处理", en: "Custom" }
  },
  GainControl: {
    "0": { zh: "无", en: "None" },
    "1": { zh: "低增益", en: "Low gain" },
    "2": { zh: "高增益", en: "High gain" },
    "3": { zh: "低衰减", en: "Low attenuation" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
  },
  ColorSpace: {
    "0": { zh: "未校准", en: "Uncalibrated" },
    "1": { zh: "sRGB", en: "sRGB" },
    "2": { zh: "Adobe RGB", en: "Adobe RGB" },
    "65535": { zh: "未校准", en: "Uncalibrated" },
    "srgb": { zh: "sRGB", en: "sRGB" },
    "adobe rgb": { zh: "Adobe RGB", en: "Adobe RGB" },
    "uncalibrated": { zh: "未校准", en: "Uncalibrated" }
  },
  Compression: {
    "1": { zh: "未压缩", en: "Uncompressed" },
    "6": { zh: "JPEG", en: "JPEG" },
    "7": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
    "8": { zh: "旋转 270° 顺时针", en: "Rotate 270 CW" },
    "32773": { zh: "PackBits", en: "PackBits" }
  },
  PhotometricInterpretation: {
    "0": { zh: "白黑", en: "White is zero" },
    "1": { zh: "黑白", en: "Black is zero" },
    "2": { zh: "RGB", en: "RGB" },
    "3": { zh: "调色板", en: "Palette" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "YCbCr", en: "YCbCr" }
  },
  ResolutionUnit: {
    "0": { zh: "未指定", en: "Unspecified" },
    "1": { zh: "无", en: "None" },
    "2": { zh: "英寸", en: "Inch" },
    "3": { zh: "厘米", en: "cm" }
  },
  YCbCrPositioning: {
    "1": { zh: "居中", en: "Centered" },
    "2": { zh: "共位", en: "Co-sited" }
  },
  ComponentsConfiguration: {
    "0": { zh: "无", en: "None" },
    "1": { zh: "Y", en: "Y" },
    "2": { zh: "Cb", en: "Cb" },
    "3": { zh: "Cr", en: "Cr" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "B", en: "B" }
  },
  FileSource: {
    "3": { zh: "数码相机", en: "Digital camera" }
  },
  SceneType: {
    "1": { zh: "直接拍摄", en: "Directly photographed" }
  },
  GPSLatitudeRef: {
    "n": { zh: "北纬", en: "North" },
    "s": { zh: "南纬", en: "South" }
  },
  GPSLongitudeRef: {
    "e": { zh: "东经", en: "East" },
    "w": { zh: "西经", en: "West" }
  },
  GPSAltitudeRef: {
    "0": { zh: "海平面以上", en: "Above sea level" },
    "1": { zh: "海平面以下", en: "Below sea level" }
  },
  GPSStatus: {
    "a": { zh: "定位中", en: "Measurement in progress" },
    "v": { zh: "定位无效", en: "Interoperability" }
  },
  GPSMeasureMode: {
    "2": { zh: "二维定位", en: "2D" },
    "3": { zh: "三维定位", en: "3D" }
  },
  GPSDifferential: {
    "0": { zh: "未校正", en: "No correction" },
    "1": { zh: "已差分校正", en: "Differential corrected" }
  },
  LightSource: {
    "0": { zh: "未知", en: "Unknown" },
    "1": { zh: "日光", en: "Daylight" },
    "2": { zh: "荧光灯", en: "Fluorescent" },
    "3": { zh: "钨丝灯", en: "Tungsten" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "9": { zh: "晴空", en: "Fine weather" },
    "10": { zh: "阴天", en: "Cloudy" },
    "11": { zh: "阴影", en: "Shade" },
    "17": { zh: "标准光 A", en: "Standard light A" },
    "18": { zh: "标准光 B", en: "Standard light B" },
    "19": { zh: "标准光 C", en: "Standard light C" },
    "255": { zh: "其他", en: "Other" }
  },
  SensitivityType: {
    "0": { zh: "未知", en: "Unknown" },
    "1": { zh: "标准输出感光度", en: "SOS" },
    "2": { zh: "推荐曝光指数", en: "REI" },
    "3": { zh: "ISO 速度", en: "ISO speed" },
    "4": { zh: "垂直翻转", en: "Mirror vertical" },
    "5": { zh: "旋转 90° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 270 CW" },
    "6": { zh: "ISO 速度 (SOS 近似)", en: "ISO speed (SOS approx)" },
    "7": { zh: "旋转 270° 顺时针 + 水平翻转", en: "Mirror horizontal and rotate 90 CW" },
  }
};

/** Returns the localized field label; falls back to the raw tag when unknown. */
export function exifFieldLabel(key: string, isEnglish: boolean): string {
  const name = resolveTagName(key);
  const label = EXIF_FIELD_LABELS[name];
  if (!label) return isEnglish ? name : key;
  return isEnglish ? (label.en || name) : label.zh;
}

/** Returns a localized enum value, or null when the value is not an enum we translate. */
export function exifValueLabel(key: string, raw: unknown, isEnglish: boolean): string | null {
  const name = resolveTagName(key);
  const map = EXIF_VALUE_LABELS[name];
  if (!map || raw == null) return null;
  const asString = String(raw);
  const hit = map[asString] ?? (typeof raw === "string" ? map[raw.trim().toLowerCase()] : undefined);
  if (!hit) return null;
  return isEnglish ? (hit.en || asString) : hit.zh;
}
