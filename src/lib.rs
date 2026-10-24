//! TTIA 1.5 vehicle-telemetry dissector for Wireshark, written in Rust with wsdf.
//!
//! Port of TTIA1.5.lua. Transport: UDP port 3806, one datagram = one TTIA packet.
//! Payload starts with ASCII "APTS". Header CustID/CarID/DriverID are big-endian;
//! Seq, Length and every multi-byte payload field are little-endian.
//!
//! Differences from the Lua version:
//! * No "@cee:{...}" JSON in the Info column (wsdf exposes no column API).
//! * The Reg_A schedule value-map lookup uses the schedule byte itself (the Lua
//!   code looked up the Result byte by mistake).
//! * Reg filename entries (FileNum x 10 bytes) are not decoded, like the Lua.
//!
//! Build & install (Wireshark 4.6, macOS, works for both Homebrew tshark and
//! the Wireshark.app GUI):
//!
//! ```sh
//! PKG_CONFIG_LIBDIR=<dir with a wireshark.pc linking only -lwireshark> \
//!     cargo build --release
//! cp target/release/libttia_vt_dissector.dylib /tmp/ttia_stage.so
//! install_name_tool -change /opt/homebrew/opt/wireshark/lib/libwireshark.19.dylib \
//!     @rpath/libwireshark.19.dylib /tmp/ttia_stage.so
//! codesign -f -s - /tmp/ttia_stage.so
//! rm -f ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
//! cp /tmp/ttia_stage.so ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
//! ```
//!
//! Note: on macOS the plugin file must be named `*.so`, and it must not be
//! overwritten in place (re-copy after `rm`, then re-sign, or dyld kills
//! tshark with SIGKILL "Code Signature Invalid"). Only one dissector can own
//! UDP port 3806, so TTIA1.5.lua is renamed to `TTIA1_5.lua_` (the usual
//! "disabled" convention) when this plugin is installed.

// Fields are read by wsdf-generated dissector code, not by Rust code.
#![allow(dead_code)]

use wsdf::tap::{Field, Offset, Packet};
use wsdf::{version, Dispatch, ProtocolField};

// Plugin 0.1.0, built for Wireshark 4.6.x (matches the local install).
version!("0.1.0", 4, 6);

// Wireshark >= 4.4 asks plugins to describe themselves before loading.
// This plugin is an epan dissector: WS_PLUGIN_DESC_EPAN | WS_PLUGIN_DESC_DISSECTOR.
#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    (1 << 3) | (1 << 0)
}

// epan-sys's pre-generated bindings declare the old `tvb_get_g[u]int*`
// functions, which Wireshark 4.6 turned into static inline wrappers around
// `tvb_get_[u]int*`. Provide the old symbols so the plugin links.
unsafe extern "C" {
    fn tvb_get_uint8(tvb: *mut wsdf::epan_sys::tvbuff, offset: std::ffi::c_int) -> u8;
    fn tvb_get_int8(tvb: *mut wsdf::epan_sys::tvbuff, offset: std::ffi::c_int) -> i8;
    fn tvb_get_uint16(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u16;
    fn tvb_get_int16(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i16;
    fn tvb_get_uint24(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u32;
    fn tvb_get_int24(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i32;
    fn tvb_get_uint32(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u32;
    fn tvb_get_int32(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i32;
    fn tvb_get_uint40(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u64;
    fn tvb_get_int40(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i64;
    fn tvb_get_uint48(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u64;
    fn tvb_get_int48(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i64;
    fn tvb_get_uint56(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u64;
    fn tvb_get_int56(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i64;
    fn tvb_get_uint64(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> u64;
    fn tvb_get_int64(
        tvb: *mut wsdf::epan_sys::tvbuff,
        offset: std::ffi::c_int,
        encoding: std::ffi::c_uint,
    ) -> i64;
}

#[no_mangle]
pub unsafe extern "C" fn tvb_get_guint8(tvb: *mut wsdf::epan_sys::tvbuff, offset: std::ffi::c_int) -> u8 {
    tvb_get_uint8(tvb, offset)
}

#[no_mangle]
pub unsafe extern "C" fn tvb_get_gint8(tvb: *mut wsdf::epan_sys::tvbuff, offset: std::ffi::c_int) -> i8 {
    tvb_get_int8(tvb, offset)
}

macro_rules! shim_tvb_get {
    ($old:ident, $new:ident, $ret:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn $old(
            tvb: *mut wsdf::epan_sys::tvbuff,
            offset: std::ffi::c_int,
            encoding: std::ffi::c_uint,
        ) -> $ret {
            $new(tvb, offset, encoding)
        }
    };
}

shim_tvb_get!(tvb_get_guint16, tvb_get_uint16, u16);
shim_tvb_get!(tvb_get_gint16, tvb_get_int16, i16);
shim_tvb_get!(tvb_get_guint24, tvb_get_uint24, u32);
shim_tvb_get!(tvb_get_gint24, tvb_get_int24, i32);
shim_tvb_get!(tvb_get_guint32, tvb_get_uint32, u32);
shim_tvb_get!(tvb_get_gint32, tvb_get_int32, i32);
shim_tvb_get!(tvb_get_guint40, tvb_get_uint40, u64);
shim_tvb_get!(tvb_get_gint40, tvb_get_int40, i64);
shim_tvb_get!(tvb_get_guint48, tvb_get_uint48, u64);
shim_tvb_get!(tvb_get_gint48, tvb_get_int48, i64);
shim_tvb_get!(tvb_get_guint56, tvb_get_uint56, u64);
shim_tvb_get!(tvb_get_gint56, tvb_get_int56, i64);
shim_tvb_get!(tvb_get_guint64, tvb_get_uint64, u64);
shim_tvb_get!(tvb_get_gint64, tvb_get_int64, i64);

// ---------------------------------------------------------------------------
// Value maps (wire value -> display name)
// ---------------------------------------------------------------------------

fn msgid_name(v: u8) -> &'static str {
    match v {
        0x00 => "Reg",
        0x01 => "Reg_A",
        0x02 => "RouteUdp",
        0x03 => "RouteUpd_A",
        0x04 => "GPS",
        0x05 => "GPS_A",
        0x06 => "SendMsg",
        0x07 => "SendMsg_A",
        0x08 => "Evt",
        0x09 => "Evt_A",
        0x0A => "ACC",
        0x0B => "ACC_A",
        0x28 => "Debug",
        0x29 => "Debug_A",
        0xF0 => "Malfunc",
        0xF1 => "Malfunc_A",
        0xF2 => "OD",
        0xF3 => "OD_A",
        _ => "Unknown",
    }
}

fn duty_status_name(v: u8) -> &'static str {
    match v {
        0x00 => "0",
        0x01 => "Normal",
        0x02 => "Start",
        0x04 => "End",
        0x08 => "Full",
        0x10 => "Couch",
        _ => "Unknown",
    }
}

fn bus_status_name(v: u8) -> &'static str {
    match v {
        0x01 => "Normal",
        0x02 => "Accident",
        0x04 => "OutOfWork",
        0x08 => "Jam",
        0x10 => "Help",
        0x20 => "Gas/washing",
        0x40 => "OffDuty",
        _ => "Unknown",
    }
}

fn event_type_name(v: u16) -> &'static str {
    match v {
        0x0001 => "Arrival/Departure",
        0x0002 => "Speeding",
        0x0004 => "Accerlate",
        0x0008 => "Door Open",
        0x0010 => "Abnormal",
        0x0020 => "StatusChange",
        0x0040 => "Run without schedule",
        0x0080 => "Driver Ack",
        0x0100 => "Zone",
        0x8000 => "Run without route",
        _ => "Unknown",
    }
}

fn gps_status_name(v: u8) -> &'static str {
    match v {
        0 => "0 (V)",
        1 => "1 (A)",
        2 => " (Coach bus)",
        _ => "Unknown",
    }
}

fn schedule_name(v: u8) -> &'static str {
    match v {
        0 => " (Non-schedule)",
        1 => " (Scheduled)",
        2 => " (Coach bus)",
        _ => "",
    }
}

fn arrival_departure_name(v: u8) -> &'static str {
    match v {
        0 => "Departure",
        1 => "Arrival",
        _ => "Unknown",
    }
}

fn door_open_name(v: u8) -> &'static str {
    match v {
        0 => "NotOpen",
        1 => "Open",
        _ => "Unknown",
    }
}

fn speed_name(v: u8) -> &'static str {
    match v {
        0 => "OverRPM",
        1 => "OverSpeed",
        _ => "Unknown",
    }
}

fn acceleration_name(v: u8) -> &'static str {
    match v {
        1 => "Acc",
        2 => "Decel",
        _ => "Unknown",
    }
}

fn door_type_name(v: u8) -> &'static str {
    match v {
        1 => "FrontDoor",
        2 => "RearDoor",
        _ => "Unknown",
    }
}

fn abnormal_type_name(v: u8) -> &'static str {
    match v {
        1 => "Park with engine on",
        2 => "Unusal moving",
        _ => "Unknown",
    }
}

fn abnormal_flag_name(v: u8) -> &'static str {
    match v {
        1 => "Start",
        2 => "End",
        _ => "Unknown",
    }
}

fn reg_type_name(v: u8) -> &'static str {
    match v {
        0 => "Cold Start",
        1 => "Warm Start",
        _ => "Unknown",
    }
}

fn driver_id_type_name(v: u8) -> &'static str {
    match v {
        0 => "IDDevice",
        1 => "Manual",
        2 => "unkown",
        _ => "Unknown",
    }
}

fn mal_module_name(v: u8) -> &'static str {
    match v {
        1 => "GPS",
        2 => "LCD",
        3 => "LED",
        4 => "DCR",
        _ => "Unknown",
    }
}

fn mal_status_name(v: u8) -> &'static str {
    match v {
        0 => "Recovery",
        1 => "No Response",
        2 => "Antena Fail",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// decode_with / consume_with helpers
// ---------------------------------------------------------------------------

/// ASCII bytes, truncated at the first NUL.
fn ascii_trim(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn decode_msgid(Field(v): Field<u8>) -> String {
    format!("{} (0x{:02x})", msgid_name(v), v)
}

fn decode_duty_status(Field(v): Field<u8>) -> String {
    duty_status_name(v).to_string()
}

fn decode_bus_status(Field(v): Field<u8>) -> String {
    bus_status_name(v).to_string()
}

fn decode_event_type(Field(v): Field<u16>) -> String {
    format!("{} (0x{:04x})", event_type_name(v), v)
}

fn decode_gps_status(Field(v): Field<u8>) -> String {
    gps_status_name(v).to_string()
}

fn decode_schedule(Field(v): Field<u8>) -> String {
    format!("{}{}", v, schedule_name(v))
}

/// Route branch byte: ASCII letter when non-zero, '0' otherwise.
fn decode_branch(Field(v): Field<u8>) -> String {
    if v > 0 && v.is_ascii_graphic() {
        (v as char).to_string()
    } else if v > 0 {
        format!("0x{:02x}", v)
    } else {
        "0".to_string()
    }
}

/// Degrees + minutes + minutes*10^4 -> decimal degrees (like the Lua).
/// 4 bytes: deg (1), min (1), min-frac x10^4 (2, little-endian).
fn decode_coord(Field(b): Field<&[u8]>) -> String {
    let deg = b[0] as f64;
    let min = b[1] as f64;
    let frac = u16::from_le_bytes([b[2], b[3]]) as f64;
    format!("{:.6}", deg + (min + frac / 10000.0) / 60.0)
}

/// GPS date: 3 bytes Y M D, year = 2000 + Y.
fn decode_gps_date(Field(b): Field<&[u8]>) -> String {
    format!("20{:02}-{:02}-{:02}", b[0], b[1], b[2])
}

/// GPS time: 3 bytes h m s.
fn decode_gps_time(Field(b): Field<&[u8]>) -> String {
    format!("{:02}:{:02}:{:02}", b[0], b[1], b[2])
}

/// OD time: 6 bytes Y M D h m s, year = 2000 + Y.
fn decode_od_time(Field(b): Field<&[u8]>) -> String {
    format!(
        "20{:02}/{:02}/{:02} {:02}:{:02}:{:02}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

/// Debug body: free-form ASCII to the end of the packet; "@BG ..." vendor
/// reports get their parts called out, like the Lua's partial decode.
fn consume_debug(Packet(packet): Packet, Offset(offset): Offset) -> (usize, String) {
    let n = packet.len() - offset;
    let text = ascii_trim(&packet[offset..]);
    let mut display = text.clone();

    if text.starts_with("@BG") && offset + 51 <= packet.len() {
        let part = |r: std::ops::Range<usize>| ascii_trim(&packet[offset + r.start..offset + r.end]);
        let mut lat: f64 = part(25..34).parse().unwrap_or(0.0) / 1_000_000.0;
        let mut lng: f64 = part(34..42).parse().unwrap_or(0.0) / 1_000_000.0;
        lat = lat.floor() + (lat % 1.0) / 0.6;
        lng = lng.floor() + (lng % 1.0) / 0.6;
        display = format!(
            "{} [comp/field: {}, route: {}, lat: {}, lng: {}, speed: {}, azimuth: {}, dir: {}]",
            text,
            part(3..7),
            part(12..18),
            lat,
            lng,
            part(42..45),
            part(45..48),
            part(48..51),
        );
    }

    (n, display)
}

/// Bodies of the *_A ack messages (and other not-decoded messages): carry no
/// fields, but must exist — wsdf cannot add a subtree at the very end of the
/// tvb, so a bodyless unit variant would make epan throw on empty acks.
#[derive(ProtocolField)]
struct AckBody(#[wsdf(consume_with = "consume_ack", hide)] Vec<u8>);

/// Swallow any remaining bytes silently.
fn consume_ack(Packet(packet): Packet, Offset(offset): Offset) -> (usize, String) {
    (packet.len() - offset, String::new())
}

// ---------------------------------------------------------------------------
// Shared payload structures
// ---------------------------------------------------------------------------

/// 22-byte GPS struct.
#[derive(ProtocolField)]
struct Gps {
    #[wsdf(rename = "Satellite No.")]
    satellites: u8,
    #[wsdf(decode_with = "decode_gps_status")]
    fix: u8,
    /// deg (1) + min (1) + min-frac x10^4 LE (2), shown as decimal degrees.
    #[wsdf(decode_with = "decode_coord", rename = "Lng.")]
    lng: [u8; 4],
    #[wsdf(rename = "Lng.Quadrant")]
    lng_quadrant: [u8; 1],
    #[wsdf(decode_with = "decode_coord", rename = "Lat.")]
    lat: [u8; 4],
    #[wsdf(rename = "Lat.Quadrant")]
    lat_quadrant: [u8; 1],
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    heading: u16,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "int. speed")]
    speed: u16,
    #[wsdf(decode_with = "decode_gps_date")]
    date: [u8; 3],
    #[wsdf(decode_with = "decode_gps_time")]
    time: [u8; 3],
}

/// MonitorStruct2 (30 bytes): GPS struct + AvgSpeed/Duty/Bus/Mileage.
#[derive(ProtocolField)]
struct Monitor2 {
    gps: Gps,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    avg_speed: u16,
    #[wsdf(decode_with = "decode_duty_status")]
    duty_status: u8,
    #[wsdf(decode_with = "decode_bus_status")]
    bus_status: u8,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    mileage: u32,
}

/// MonitorStruct1 (110 bytes): GPS struct + AvgSpeed + 20-sample histories.
#[derive(ProtocolField)]
struct Monitor1 {
    gps: Gps,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    avg_speed: u16,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    int_speed: [u16; 20],
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    rpm: [u16; 20],
    #[wsdf(decode_with = "decode_duty_status")]
    duty_status: u8,
    #[wsdf(decode_with = "decode_bus_status")]
    bus_status: u8,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    mileage: u32,
}

// ---------------------------------------------------------------------------
// MsgID (0x08) event bodies, dispatched by EvtType; payload starts at 56
// ---------------------------------------------------------------------------

#[derive(ProtocolField, Dispatch)]
enum EventDetail {
    /// 進出站(圓形偵測) — stop arrival/departure
    Arrival {
        #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
        stop: u16,
        #[wsdf(decode_with = "decode_arrival_departure", rename = "eType")]
        atd: u8,
        #[wsdf(decode_with = "decode_door_open")]
        door: u8,
    },
    /// 超轉超速 — over-RPM / over-speed
    Speeding {
        #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
        stop: u16,
        #[wsdf(decode_with = "decode_speed", rename = "eType")]
        kind: u8,
        #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
        value: u16,
    },
    /// 急加/減速 — hard acceleration / braking
    Acceleration {
        #[wsdf(decode_with = "decode_acceleration", rename = "Type")]
        kind: u8,
        #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "Speed(km/hr)")]
        value: u16,
    },
    /// 行駛中前門/後門開啟 — door opened while driving
    DoorOpen {
        #[wsdf(decode_with = "decode_door_type", rename = "Type")]
        door: u8,
    },
    /// 車輛異常回報 — 停車不熄火 or 異常移動
    Abnormal {
        #[wsdf(decode_with = "decode_abnormal_type", rename = "Type")]
        kind: u8,
        #[wsdf(decode_with = "decode_abnormal_flag")]
        flag: u8,
    },
    /// 司機由螢幕改變車輛狀態(包含緊急事件)
    StatusChange {
        #[wsdf(decode_with = "decode_duty_status", rename = "Type")]
        mode: u8,
        #[wsdf(decode_with = "decode_duty_status")]
        pre_mode: u8,
    },
    /// 異常發車 — departed without a schedule
    NonSchedule {
        #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "Run Distance(10m)")]
        run_dis: u16,
    },
    /// 司機回覆 — driver reply to a message
    DriverAck {
        #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "Info ID")]
        info_id: u16,
        #[wsdf(rename = "Driver Ack Reply")]
        reply: u8,
    },
    /// 進出特定區域 — geofence enter/leave
    EnterZone {
        #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "Region ID")]
        region_id: u16,
    },
    /// 路線外營運 — operating off route (no body)
    OutRoute,
    Unknown,
}

fn decode_arrival_departure(Field(v): Field<u8>) -> String {
    arrival_departure_name(v).to_string()
}
fn decode_door_open(Field(v): Field<u8>) -> String {
    door_open_name(v).to_string()
}
fn decode_speed(Field(v): Field<u8>) -> String {
    speed_name(v).to_string()
}
fn decode_acceleration(Field(v): Field<u8>) -> String {
    acceleration_name(v).to_string()
}
fn decode_door_type(Field(v): Field<u8>) -> String {
    door_type_name(v).to_string()
}
fn decode_abnormal_type(Field(v): Field<u8>) -> String {
    abnormal_type_name(v).to_string()
}
fn decode_abnormal_flag(Field(v): Field<u8>) -> String {
    abnormal_flag_name(v).to_string()
}

// ---------------------------------------------------------------------------
// Per-message payloads (dispatched by MsgID)
// ---------------------------------------------------------------------------

/// 0x00 Reg
#[derive(ProtocolField)]
struct RegBody {
    monitor: Monitor2,
    #[wsdf(decode_with = "decode_ascii_field")]
    imsi: [u8; 15],
    #[wsdf(decode_with = "decode_ascii_field")]
    imei: [u8; 15],
    vendor: u8,
    #[wsdf(decode_with = "decode_ascii_field", rename = "OBUVer")]
    obu_ver: [u8; 8],
    #[wsdf(decode_with = "decode_reg_type")]
    reg_type: u8,
    #[wsdf(decode_with = "decode_driver_id_type", rename = "DriverID Mode")]
    driver_id_mode: u8,
    #[wsdf(rename = "FileNumber")]
    file_num: u8,
    // FileNum x 10-byte filename entries follow (not decoded, like the Lua).
}

fn decode_ascii_field(Field(b): Field<&[u8]>) -> String {
    ascii_trim(b)
}
fn decode_reg_type(Field(v): Field<u8>) -> String {
    reg_type_name(v).to_string()
}
fn decode_driver_id_type(Field(v): Field<u8>) -> String {
    driver_id_type_name(v).to_string()
}

/// 0x01 Reg_A
#[derive(ProtocolField)]
struct RegAck {
    result: u8,
    #[wsdf(decode_with = "decode_schedule")]
    schedule: u8,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    route_id: u16,
    #[wsdf(rename = "Route Dir")]
    dir: u8,
    #[wsdf(decode_with = "decode_branch", rename = "Route Branch")]
    branch: u8,
}

/// 0x02 RouteUpd (route change)
#[derive(ProtocolField)]
struct RouteChange {
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    route_id: u16,
    #[wsdf(rename = "Route Dir")]
    dir: u8,
    #[wsdf(decode_with = "decode_branch", rename = "Route Branch")]
    branch: u8,
}

/// 0x04 GPS: Count x MonitorStruct1. A gap byte sits between Count and the
/// first struct (the Lua decoded structs from absolute offset 22).
#[derive(ProtocolField)]
struct GpsList {
    count: u8,
    #[wsdf(hide)]
    gap: u8,
    #[wsdf(len_field = "count")]
    reports: Vec<Monitor1>,
}

/// 0x08 Evt
#[derive(ProtocolField)]
struct Event {
    #[wsdf(decode_with = "decode_event_type", enc = "ENC_LITTLE_ENDIAN", rename = "EventType")]
    event_type: u16,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    route_id: u16,
    #[wsdf(rename = "Route Dir")]
    dir: u8,
    #[wsdf(decode_with = "decode_branch", rename = "Route Branch")]
    branch: u8,
    monitor: Monitor2,
    #[wsdf(dispatch_field = "event_type")]
    detail: EventDetail,
}

impl EventDetail {
    fn dispatch_event_type(event_type: &u16) -> EventDetailDispatch {
        use EventDetailDispatch::*;
        match *event_type {
            0x0001 => Arrival,
            0x0002 => Speeding,
            0x0004 => Acceleration,
            0x0008 => DoorOpen,
            0x0010 => Abnormal,
            0x0020 => StatusChange,
            0x0040 => NonSchedule,
            0x0080 => DriverAck,
            0x0100 => EnterZone,
            0x8000 => OutRoute,
            _ => Unknown,
        }
    }
}

/// 0x0A ACC (ignition on/off report)
#[derive(ProtocolField)]
struct AccReport {
    monitor: Monitor2,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    psd_reconnect: u16,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    packet_ratio: u8,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    gps_ratio: u8,
}

/// 0xF0 Malfunc
#[derive(ProtocolField)]
struct Malfunc {
    #[wsdf(decode_with = "decode_mal_module", rename = "Malfunction Module")]
    module: u8,
    #[wsdf(decode_with = "decode_mal_status", rename = "Malfunction Code")]
    code: u8,
}

fn decode_mal_module(Field(v): Field<u8>) -> String {
    mal_module_name(v).to_string()
}
fn decode_mal_status(Field(v): Field<u8>) -> String {
    mal_status_name(v).to_string()
}

/// 0xF2 OD (origin/destination ticket report)
#[derive(ProtocolField)]
struct OdReport {
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    route_id: u16,
    #[wsdf(rename = "Route Dir")]
    dir: u8,
    #[wsdf(decode_with = "decode_branch", rename = "Route Branch")]
    branch: u8,
    #[wsdf(rename = "ODRecord")]
    record_count: u8,
    reserved: u8,
    #[wsdf(len_field = "record_count")]
    records: Vec<OdRecord>,
}

#[derive(ProtocolField)]
struct OdRecord {
    org_stop: u8,
    dst_stop: u8,
    #[wsdf(decode_with = "decode_od_time", rename = "OrgODTime")]
    org_time: OdTime,
    #[wsdf(decode_with = "decode_od_time", rename = "DstODTime")]
    dst_time: OdTime,
    remaining_num: u8,
    #[wsdf(rename = "RecordNum")]
    ticket_count: u8,
    #[wsdf(len_field = "ticket_count")]
    tickets: Vec<Ticket>,
}

#[derive(ProtocolField)]
struct OdTime(#[wsdf(decode_with = "decode_od_time")] [u8; 6]);

#[derive(ProtocolField)]
struct Ticket {
    ticket_id: u8,
    #[wsdf(rename = "TickedNum")]
    ticket_num: u8,
}

/// Free-form ASCII body of 0x28 Debug.
#[derive(ProtocolField)]
struct DebugText(#[wsdf(consume_with = "consume_debug")] Vec<u8>);

#[derive(ProtocolField, Dispatch)]
enum Payload {
    Reg(RegBody),
    RegA(AckBody),
    RouteUpd(RouteChange),
    RouteUpdA(AckBody),
    Gps(GpsList),
    GpsA(AckBody),
    SendMsg(AckBody), // not decoded, like the Lua
    SendMsgA(AckBody),
    Evt(Event),
    EvtA(AckBody),
    Acc(AccReport),
    AccA(AckBody),
    Debug(DebugText),
    DebugA(AckBody),
    Malfunc(Malfunc),
    MalfuncA(AckBody),
    Od(OdReport),
    OdA(AckBody),
    Unknown(AckBody),
}

impl Payload {
    fn dispatch_msg_id(msg_id: &u8) -> PayloadDispatch {
        use PayloadDispatch::*;
        match *msg_id {
            0x00 => Reg,
            0x01 => RegA,
            0x02 => RouteUpd,
            0x03 => RouteUpdA,
            0x04 => Gps,
            0x05 => GpsA,
            0x06 => SendMsg,
            0x07 => SendMsgA,
            0x08 => Evt,
            0x09 => EvtA,
            0x0A => Acc,
            0x0B => AccA,
            0x28 => Debug,
            0x29 => DebugA,
            0xF0 => Malfunc,
            0xF1 => MalfuncA,
            0xF2 => Od,
            0xF3 => OdA,
            _ => Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Common header + protocol root
// ---------------------------------------------------------------------------
//
// The root derives ProtocolField only; registration and the dissector entry
// point are written by hand below so that a truncated packet (which would
// otherwise panic in wsdf's generated bounds code) degrades to a partial
// tree instead of aborting Wireshark.

#[derive(ProtocolField)]
struct TtiaPacket {
    #[wsdf(decode_with = "decode_protocol_id", rename = "ProtocolID")]
    protocol_id: [u8; 4],
    #[wsdf(rename = "protocol Version")]
    version: u8,
    #[wsdf(decode_with = "decode_msgid", rename = "MessageID")]
    msg_id: u8,
    #[wsdf(display = "BASE_HEX")]
    cust_id: u16,
    #[wsdf(display = "BASE_HEX")]
    car_id: u16,
    #[wsdf(rename = "StorageID")]
    storage_id: u8,
    #[wsdf(display = "BASE_HEX")]
    driver_id: u32,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN")]
    seq: u16,
    #[wsdf(hide)]
    reserved: u8,
    #[wsdf(enc = "ENC_LITTLE_ENDIAN", rename = "Length")]
    payload_len: u16,
    #[wsdf(dispatch_field = "msg_id")]
    payload: Payload,
}

fn decode_protocol_id(Field(b): Field<&[u8]>) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// Plugin entry points (hand-written; root derives ProtocolField only so a
// truncated packet degrades to a partial tree instead of aborting Wireshark)
// ---------------------------------------------------------------------------

const PROTO_NAME: &[u8] = b"TTIAVT-RS\0"; // protocol column / registered name
const PROTO_TITLE: &[u8] = b"TTIA Vehicle Telemetry protocol 1.5 (Rust)\0";
const PROTO_FILTER: &[u8] = b"ttiavt\0";
const PROTO_FILTER_STR: &str = "ttiavt";

fn cs(b: &'static [u8]) -> *const std::ffi::c_char {
    b.as_ptr() as *const std::ffi::c_char
}

#[no_mangle]
pub extern "C" fn plugin_register() {
    // proto_register_plugin keeps the pointer, so the struct must outlive this call.
    let plug: &'static mut wsdf::epan_sys::proto_plugin = Box::leak(Box::new(
        wsdf::epan_sys::proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        },
    ));
    plug.register_protoinfo = Some(proto_register);
    plug.register_handoff = Some(proto_reg_handoff);
    unsafe {
        wsdf::epan_sys::proto_register_plugin(plug);
    }
}

extern "C" fn proto_register() {
    let proto_id = unsafe {
        wsdf::epan_sys::proto_register_protocol(cs(PROTO_NAME), cs(PROTO_TITLE), cs(PROTO_FILTER))
    };
    *TtiaPacket::proto_id() = proto_id;
    TtiaPacket::register(PROTO_FILTER_STR, proto_id,
        wsdf::FieldIdent::null(), wsdf::FieldBlurb::null());
    std::panic::set_hook(Box::new(|_| {})); // truncated packets: no stderr spam
}

extern "C" fn proto_reg_handoff() {
    unsafe {
        let handle = wsdf::epan_sys::create_dissector_handle(
            Some(dissect_main), *TtiaPacket::proto_id());
        wsdf::epan_sys::dissector_add_uint(cs(b"udp.port\0"), 3806, handle);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dissect_main(
    tvb: *mut wsdf::epan_sys::tvbuff,
    pinfo: *mut wsdf::epan_sys::_packet_info,
    tree: *mut wsdf::epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let cinfo = (*pinfo).cinfo;
    if !cinfo.is_null() {
        wsdf::epan_sys::col_set_str(cinfo, wsdf::epan_sys::COL_PROTOCOL as std::ffi::c_int, cs(PROTO_NAME));
        wsdf::epan_sys::col_clear(cinfo, wsdf::epan_sys::COL_INFO as std::ffi::c_int);
    }
    let len = wsdf::epan_sys::tvb_reported_length(tvb) as usize;
    let mut buf = vec![0u8; len];
    wsdf::epan_sys::tvb_memcpy(tvb, buf.as_mut_ptr() as *mut std::ffi::c_void, 0, len);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        TtiaPacket::dissect(0, tvb, tree, PROTO_FILTER_STR,
            wsdf::VariantDispatch::None, wsdf::SubtreeLabel::new(cs(PROTO_NAME)),
            &buf, pinfo, tree, &mut wsdf::FieldsStore::default())
    }));
    result.unwrap_or(0)
}
