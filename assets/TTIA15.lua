 ---------------------------------------------------------------------------
-- TTIA 1.5 vehicle-telemetry dissector for Wireshark (Lua)
--
-- Transport : UDP port 3806, one datagram = one TTIA packet.
-- Magic     : payload starts with ASCII "APTS" (not enforced here).
-- Byte order: CustID/CarID/DriverID in the header are big-endian;
--             Seq, Length and every multi-byte payload field are
--             little-endian.
--
-- Each packet is decoded twice:
--   * into the packet-details tree (human readable), and
--   * into the Info column as one flat CEE/JSON object ("@cee:{...}",
--     consumed downstream by rsyslog mmjsonparse / Lumberjack).
-- show_num/show_str below produce both at once.
--
-- Packet = header (20 bytes) + payload:
--
--   Off  Size  Field
--   ---  ----  ----------------------------------
--   0    4     ProtocolID   ASCII "APTS"
--   4    1     Version      0x15 = 1.5
--   5    1     MsgID        selects payload layout (MSG_DISSECTOR)
--   6    2     CustID       customer/operator id
--   8    2     CarID        vehicle id
--   10   1     StorageID
--   11   4     DriverID
--   15   2     Seq          (little-endian)
--   17   1     Reserved
--   18   2     PayloadLen   (little-endian)
--
-- Payload layouts (multi-byte fields little-endian; payload starts at 20):
--
--   Reg      0x00: MonitorStruct2@20 | IMSI 50(15) IMEI 65(15) Vendor 80
--                  OBUVer 81(8) RegType 89 DriverIDMode 90 FileNum 91
--                  (+ FileNum x 10-byte filename entries @92, not decoded)
--   Reg_A    0x01: Result 20 Schedule 21 RouteID 22 Dir 24 Branch 25
--   RouteUpd 0x02: RouteID 20 Dir 22 Branch 23
--   GPS      0x04: Count 20(1), then Count x MonitorStruct1 from 22
--   Evt      0x08: EvtType 20(2) RouteID 22(2) Dir 24 Branch 25
--                  MonitorStruct2@26, then EvtType-specific body @56
--   ACC      0x0A: MonitorStruct2@20 | PSDReconnect 50(2) PacketRatio 52
--                  GPSRatio 53
--   Malfunc  0xF0: Module 20 Code 21
--   OD       0xF2: RouteID 20(2) Dir 22 Branch 23 RecordCount 24
--                  Reserved 25, then records from 26 (list_od_record)
--   Debug    0x28: ASCII text at 20, length = header Length field;
--                  "@BG ..." vendor report partially decoded
--   *_A (0x05 0x07 0x09 0x0B 0x29 0xF1 0xF3): acks, no body decoded
--
-- MonitorStruct1 (110 bytes):
--   GPS struct @0 (22 bytes, decode_gps)
--   22    2   AvgSpeed
--   24   40   IntSpeed: 20 x uint16 samples
--   64   40   RPM:      20 x uint16 samples
--   104   1   DutyStatus
--   105   1   BusStatus
--   106   4   Mileage
--
-- MonitorStruct2 (30 bytes):
--   GPS struct @0, AvgSpeed 22(2), DutyStatus 24, BusStatus 25, Mileage 26(4)
--
-- GPS struct (22 bytes):
--    0   1   Satellite count
--    1   1   Fix status (0 = 'V', 1 = 'A')
--    2   1   Longitude degrees
--    3   1   Longitude minutes
--    4   2   Longitude minutes, 4 decimals (x10^4)
--    6   1   Longitude quadrant ('E'/'W')
--    7..11   Latitude, same layout (quadrant @11)
--   12   2   Heading (degrees)
--   14   2   Speed
--   16   6   Date/time: Y M D h m s (year = 2000 + Y)
 ---------------------------------------------------------------------------
 do
	local p_TTIAVT = Proto("a_ttiavt2","TTIA_VT protocol 1.5")

	------------------------------------------------------------------------
	-- Configuration
	------------------------------------------------------------------------
	local l_outputJSON = true  -- Info column as full JSON
	local l_cee = true         -- '@cee:' prefix (rsyslog mmjsonparse/Lumberjack)
	local show_fld = true      -- false = values only (csv style)
	local hide_gps = false     -- true = omit GPS fields from the Info column
	local table_concat_sep = ','

	------------------------------------------------------------------------
	-- Layout constants
	------------------------------------------------------------------------
	local HDR_LEN = 20
	local MONITOR1_LEN = 110
	local MONITOR2_LEN = 30
	local EVT_PAYLOAD_OFF = 26 + MONITOR2_LEN -- Evt: fixed part 20..25 + MonitorStruct2 26..55

	------------------------------------------------------------------------
	-- Value maps (wire value -> display name)
	------------------------------------------------------------------------
	local MSGID = {
		[0x00] = "Reg",      [0x01] = "Reg_A",
		[0x02] = "RouteUdp", [0x03] = "RouteUpd_A",
		[0x04] = "GPS",      [0x05] = "GPS_A",
		[0x06] = "SendMsg",  [0x07] = "SendMsg_A",
		[0x08] = "Evt",      [0x09] = "Evt_A",
		[0x0A] = "ACC",      [0x0B] = "ACC_A",
		[0x28] = "Debug",    [0x29] = "Debug_A",
		[0xF0] = "Malfunc",  [0xF1] = "Malfunc_A",
		[0xF2] = "OD",       [0xF3] = "OD_A"
	}

	local DUTY_STATUS = {
		[0x00] = "0",
		[0x01] = "Normal",
		[0x02] = "Start",
		[0x04] = "End",
		[0x08] = "Full",
		[0x10] = "Couch"
	}

	local BUS_STATUS = {
		[0x01] = "Normal",
		[0x02] = "Accident",
		[0x04] = "OutOfWork",
		[0x08] = "Jam",
		[0x10] = "Help",
		[0x20] = "Gas/washing",
		[0x40] = "OffDuty"
	}

	local EVENT_TYPE = {
		[0x0001] = "Arrival/Departure", --進出站(圓形偵測)
		[0x0002] = "Speeding", --超轉超速
		[0x0004] = "Accerlate", --急加/減速
		[0x0008] = "Door Open",--行駛中前門/後門開啟
		[0x0010] = "Abnormal", -- 車輛異常回報. 停車不熄火 or 異常移動
		[0x0020] = "StatusChange", -- 車輛狀態 司機由螢幕改變車輛狀態(包含緊急事件)
		[0x0040] = "Run without schedule", --異常發車
		[0x0080] = "Driver Ack", -- 司機回覆
		[0x0100] = "Zone", --進出特定區域
		[0x8000] = "Run without route" --路線外營運
	}

	local GPS_STATUS = {
		[0] = "0 (V)",
		[1] = "1 (A)",
		[2] = " (Coach bus)"
	}

	local SCHEDULE = {
		[0] = " (Non-schedule)",
		[1] = " (Scheduled)",
		[2] = " (Coach bus)"
	}

	local ARRIVAL_DEPARTURE = {
		[0] = "Departure",
		[1] = "Arrival"
	}

	local DOOR_OPEN = {
		[0] = "NotOpen",
		[1] = "Open"
	}

	local SPEED = {
		[0] = "OverRPM",
		[1] = "OverSpeed"
	}

	local ACCELERATION = {
		[1] = "Acc",
		[2] = "Decel"
	}

	local DOOR_TYPE = {
		[1] = "FrontDoor",
		[2] = "RearDoor"
	}

	local ABNORMAL_TYPE = {
		[1] = "Park with engine on",
		[2] = "Unusal moving"
	}

	local ABNORMAL_FLAG = {
		[1] = "Start",
		[2] = "End"
	}

	local REG_TYPE = {
		[0] = "Cold Start",
		[1] = "Warm Start"
	}

	local DRIVER_ID_TYPE = {
		[0] = "IDDevice",
		[1] = "Manual",
		[2] = "unkown"
	}

	local MAL_MODULE = {
		[1] = "GPS",
		[2] = "LCD",
		[3] = "LED",
		[4] = "DCR"
	}

	local MAL_STATUS = {
		[0] = "Recovery",
		[1] = "No Response",
		[2] = "Antena Fail"
	}

	------------------------------------------------------------------------
	-- ProtoField declarations (filter names must stay stable)
	------------------------------------------------------------------------
	local f_msgID       = ProtoField.uint8 ("TTIAVT.MsgID","MessageID",base.HEX,MSGID)
	local f_CustID      = ProtoField.uint16("TTIAVT.CustID","CustomerID",base.HEX)
	local f_CarID       = ProtoField.uint16("TTIAVT.CarID","CarID",base.HEX)
	local f_DriverID    = ProtoField.uint32("TTIAVT.DriverID","DriverID",base.Hex)
	local f_IMEI        = ProtoField.string("TTIAVT.imei","IMEI","IMEI")
	local f_IMSI        = ProtoField.string("TTIAVT.imsi","IMSI","IMSI")
	local f_OBUVersion  = ProtoField.string("TTIAVT.OBUVer","OBUVer","OBUVer")
	local f_seq         = ProtoField.uint16("TTIAVT.seq","Sequnce",base.DEC)
	local f_routeid     = ProtoField.uint16("TTIAVT.RouteID","RouteID",base.DEC)
	local f_debugRoute  = ProtoField.string("TTIAVT.debugRoute","debugRoute","debugRoute")
	local f_debugStopSeq= ProtoField.uint8 ("TTIAVT.DebugStopSeq","DebugStopSeq",base.hex)
	local f_DutyStatus  = ProtoField.uint8 ("TTIAVT.Duty","DutyStatus",base.HEX, DUTY_STATUS)
	local f_BusStatus   = ProtoField.uint8 ("TTIAVT.Bus","BusStatus",base.HEX, BUS_STATUS)
	local f_EventType   = ProtoField.uint16("TTIAVT.EventType","EventType",base.HEX, EVENT_TYPE)

	p_TTIAVT.fields = {f_msgID,f_CustID,f_CarID,f_DriverID,f_IMEI,f_IMSI,f_seq,f_routeid,f_debugRoute,
	                   f_debugStopSeq,f_DutyStatus,f_BusStatus,f_EventType,f_OBUVersion}

	------------------------------------------------------------------------
	-- Generic helpers
	------------------------------------------------------------------------

	-- Value-map lookup: mapped name, or the raw value when unmapped.
	local function table2Value(tblName, idx)
		local v = tblName[idx]
		if v ~= nil then return v end
		return idx
	end

	-- ASCII string from buf[pos, pos+len), truncated at the first NUL.
	local function getBufStr(buf, pos, len)
		local str = buf(pos,len):string()
		local x = string.find(str, "\000", nil, true)
		if x ~= nil then str = str:sub(1, x-1) end
		return str
	end

	-- Info-column fragment builders. Field names are emitted only when
	-- show_fld is set; strings get JSON quotes, numbers stay bare.
	local function mkStrField(fld, v)
		if v == nil then v = 'nil' end
		if show_fld ~= true then return v end
		if l_outputJSON then
			return '"'..fld..'":"'..v..'"'
		end
		return fld..':'..v
	end

	local function mkNumField(fld, v)
		if v == nil then v = 0 end
		if show_fld ~= true then return v end
		if l_outputJSON then
			return '"'..fld..'":'..v
		end
		return fld..':'..v
	end

	-- Show one field in the details tree ("label: value") and collect the
	-- matching Info-column fragment into `out`. Keep calls sequential --
	-- tree display order matters.
	local function show_num(out, tree, range, label, key, v)
		tree:add(range, label .. v)
		out[#out+1] = mkNumField(key, v)
	end

	local function show_str(out, tree, range, label, key, v)
		tree:add(range, label .. v)
		out[#out+1] = mkStrField(key, v)
	end

	-- Append collected fragments to the Info column, ','-separated.
	local function emit_info(pkt, out)
		pkt.cols.info:append(table_concat_sep .. table.concat(out, table_concat_sep))
	end

	-- Route branch byte: ASCII letter when non-zero, '0' otherwise.
	local function route_branch_str(buf, off)
		if buf(off,1):uint() > 0 then return buf(off,1):string() end
		return '0'
	end

	-- "[a,b,..]" of `count` little-endian uint16 samples at buf[offset].
	local function uint16_array_str(buf, offset, count, sep)
		local res = {}
		for i = 0, count-1 do
			res[#res+1] = buf(offset + i*2, 2):le_uint()
		end
		return '['..table.concat(res, sep)..']'
	end

	------------------------------------------------------------------------
	-- Shared payload structures
	------------------------------------------------------------------------

	-- Decode the 22-byte GPS struct at buf[offset] into the tree; returns
	-- Info-column fragments (SatelliteNo/GpsStatus/PT/Dir/intSpd/d).
	local function decode_gps(buf, tree, offset)
		local strDate = string.format("20%d-%02d-%02d",
			buf(offset+16,1):uint(), buf(offset+17,1):uint(), buf(offset+18,1):uint())
		local strTime = string.format("%02d:%02d:%02d",
			buf(offset+19,1):uint(), buf(offset+20,1):uint(), buf(offset+21,1):uint())

		-- Degrees + minutes + minutes*10^4 -> decimal degrees
		local lng = buf(offset+2,1):uint() + (buf(offset+3,1):uint() + (buf(offset+4,2):le_uint() / 10000.0)) / 60.0
		local lat = buf(offset+7,1):uint() + (buf(offset+8,1):uint() + (buf(offset+9,2):le_uint() / 10000.0)) / 60.0

		tree:add(buf(offset,1),  "Satellite No.: " .. buf(offset,1):uint())
		tree:add(buf(offset+1,1),"Gps Status: " .. table2Value(GPS_STATUS, buf(offset+1,1):uint()))
		tree:add(buf(offset+2,4),"Lng.: " .. tostring(lng))
		tree:add(buf(offset+6,1),"Lng.Quadrant: " .. buf(offset+6,1):string())
		tree:add(buf(offset+7,4),"Lat.: " .. tostring(lat))
		tree:add(buf(offset+11,1),"Lng.Quadrant: " .. buf(offset+11,1):string()) -- sic: this is the lat quadrant
		tree:add(buf(offset+12,2),"Dir.: " .. buf(offset+12,2):le_uint())
		tree:add(buf(offset+14,2),"int. speed: " .. buf(offset+14,2):le_uint())
		tree:add(buf(offset+16,3), 'Date: ' .. strDate)
		tree:add(buf(offset+19,3), 'Time: ' .. strTime)

		local out = {}
		if not hide_gps then
			out[#out+1] = mkNumField("SatelliteNo", buf(offset,1):uint())
			out[#out+1] = mkNumField("GpsStatus", buf(offset+1,1):uint())
			out[#out+1] = mkStrField("PT", string.sub(lat,1,9)..','..string.sub(lng,1,9))
			out[#out+1] = mkNumField("Dir", buf(offset+12,2):le_uint())
			out[#out+1] = mkNumField("intSpd", buf(offset+14,2):le_uint())
			out[#out+1] = mkStrField("d", strDate .. ' ' .. strTime)
		end
		return out
	end

	-- MonitorStruct1 (110 bytes): GPS struct + AvgSpeed + 20-sample history.
	local function decode_monitor1(buf, tree, offset)
		local out = decode_gps(buf, tree, offset)
		local avgSpeed = buf(offset+22,2):le_uint()
		local intSpeed = uint16_array_str(buf, offset+24, 20, ",")
		local rpm      = uint16_array_str(buf, offset+64, 20, ",")

		tree:add(buf(offset+22,2),"AvgSpeed: " .. avgSpeed)
		tree:add(buf(offset+24,40),"IntSpeed: " .. intSpeed)
		tree:add(buf(offset+64,40),"RPM: " .. rpm)
		tree:add(f_DutyStatus, buf(offset+104,1))
		tree:add(f_BusStatus, buf(offset+105,1))
		tree:add(buf(offset+106,4),"Mileage: " .. buf(offset+106,4):le_uint())

		if not hide_gps then
			out[#out+1] = mkNumField("AvgSpeed", avgSpeed)
			out[#out+1] = mkNumField("IntSpeed", intSpeed)
			out[#out+1] = mkNumField("RPM", rpm)
			out[#out+1] = mkNumField("DutyStatus", buf(offset+104,1):uint())
			out[#out+1] = mkNumField("BusStatus", buf(offset+105,1):uint())
			out[#out+1] = mkNumField("Mileage", buf(offset+106,4):le_uint())
		end
		return out
	end

	-- MonitorStruct2 (30 bytes): GPS struct + AvgSpeed/Duty/Bus/Mileage.
	-- Appends the whole GPS object to the Info column itself.
	local function decode_monitor2(buf, pkt, tree, offset)
		local out = decode_gps(buf, tree, offset)
		local avgSpeed = buf(offset+22,2):le_uint()

		tree:add(buf(offset+22,2),"AvgSpeed: " .. avgSpeed)
		tree:add(f_DutyStatus, buf(offset+24,1))
		tree:add(f_BusStatus, buf(offset+25,1))
		tree:add(buf(offset+26,4),"Mileage: " .. buf(offset+26,4):le_uint())

		if not hide_gps then
			out[#out+1] = mkNumField("AvgSpeed", avgSpeed)
			out[#out+1] = mkNumField("DutyStatus", buf(offset+24,1):uint())
			out[#out+1] = mkNumField("BusStatus", buf(offset+25,1):uint())
			out[#out+1] = mkNumField("Mileage", buf(offset+26,4):le_uint())
		end
		pkt.cols.info:append(table_concat_sep .. mkNumField('GPS','[{'..table.concat(out, table_concat_sep) ..'}]'))
	end

	------------------------------------------------------------------------
	-- Evt (MsgID 0x08) bodies, dispatched by EvtType; payload starts @56
	------------------------------------------------------------------------

	-- EvtType 0x0001: 進出站(圓形偵測) — stop arrival/departure
	local function evt_arrival(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_num(out, tree, buf(o,2),   "Stop:",  "Stop",  buf(o,2):le_uint())
		show_str(out, tree, buf(o+2,1), "eType:", "eType", table2Value(ARRIVAL_DEPARTURE, buf(o+2,1):uint()))
		show_str(out, tree, buf(o+3,1), "Door:",  "Door",  table2Value(DOOR_OPEN, buf(o+3,1):uint()))
		emit_info(pkt, out)
	end

	-- EvtType 0x0002: 超轉超速 — over-RPM / over-speed
	local function evt_speed(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_num(out, tree, buf(o,2),   "Stop:",  "Stop",  buf(o,2):le_uint())
		show_str(out, tree, buf(o+2,1), "eType:", "eType", table2Value(SPEED, buf(o+2,1):uint()))
		show_num(out, tree, buf(o+3,2), "Value:", "Value", buf(o+3,2):le_uint())
		emit_info(pkt, out)
	end

	-- EvtType 0x0004: 急加/減速 — hard acceleration / braking
	local function evt_acc(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_str(out, tree, buf(o,1),   "Type:",         "eType", table2Value(ACCELERATION, buf(o,1):uint()))
		show_num(out, tree, buf(o+1,2), "Speed(km/hr>:", "Value", buf(o+1,2):le_uint())
		emit_info(pkt, out)
	end

	-- EvtType 0x0008: 行駛中前門/後門開啟 — door opened while driving
	local function evt_door_open(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_str(out, tree, buf(o,1), "Type:", "eType", table2Value(DOOR_TYPE, buf(o,1):uint()))
		emit_info(pkt, out)
	end

	-- EvtType 0x0010: 車輛異常回報 — 停車不熄火 or 異常移動
	local function evt_abnormal(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_str(out, tree, buf(o,1),   "Type:", "eType", table2Value(ABNORMAL_TYPE, buf(o,1):uint()))
		show_str(out, tree, buf(o+1,1), "Flag:", "flag",  table2Value(ABNORMAL_FLAG, buf(o+1,1):uint()))
		emit_info(pkt, out)
	end

	-- EvtType 0x0020: 司機由螢幕改變車輛狀態(包含緊急事件)
	local function evt_status_chg(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = {}
		show_str(out, tree, buf(o,1),   "Type:",    "eType",   table2Value(DUTY_STATUS, buf(o,1):uint()))
		show_str(out, tree, buf(o+1,1), "PreMode:", "PreMode", table2Value(DUTY_STATUS, buf(o+1,1):uint()))
		emit_info(pkt, out)
	end

	-- EvtType 0x0040: 異常發車 — departed without a schedule
	local function evt_non_schedule(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = { mkStrField("eType", 'abnormal Run') }
		show_num(out, tree, buf(o,2), "Run Distance(10m):", "RunDis", buf(o,2):le_uint())
		emit_info(pkt, out)
	end

	-- EvtType 0x0080: 司機回覆 — driver reply to a message
	local function evt_driver_ack(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = { mkStrField("eType", 'DriverAck') }
		show_num(out, tree, buf(o,2),   "Info ID:",          "InfoID",    buf(o,2):le_uint())
		show_num(out, tree, buf(o+2,1), "Driver Ack Reply:", "DriverAck", buf(o+2,1):uint())
		emit_info(pkt, out)
	end

	-- EvtType 0x0100: 進出特定區域 — geofence enter/leave
	local function evt_enter_zone(buf, pkt, tree)
		local o = EVT_PAYLOAD_OFF
		local out = { mkStrField("eType", 'GeoFence') }
		show_num(out, tree, buf(o,2), "Region ID :", "RegionID", buf(o,2):le_uint())
		emit_info(pkt, out)
	end

	-- EvtType 0x8000: 路線外營運 — operating off route (no body)
	local function evt_out_route(buf, pkt, tree)
		emit_info(pkt, { mkStrField("eType", 'OutRoute') })
	end

	local EVENT_DISSECTOR = {
		[0x0001] = evt_arrival,
		[0x0002] = evt_speed,
		[0x0004] = evt_acc,
		[0x0008] = evt_door_open,
		[0x0010] = evt_abnormal,
		[0x0020] = evt_status_chg,
		[0x0040] = evt_non_schedule,
		[0x0080] = evt_driver_ack,
		[0x0100] = evt_enter_zone,
		[0x8000] = evt_out_route
	}

	------------------------------------------------------------------------
	-- OD record list (MsgID 0xF2)
	------------------------------------------------------------------------

	-- OD time: "YYYY/MM/DD HH:MM:SS" from 6 bytes (year = 2000 + byte)
	local function od_time_str(buf, offset)
		return	tostring(2000 + buf(offset,1):uint()) .. "/" ..
				tostring(buf(offset+1,1):uint()) .. "/" ..
				tostring(buf(offset+2,1):uint()) .. " " ..
				tostring(buf(offset+3,1):uint()) .. ":" ..
				tostring(buf(offset+4,1):uint()) .. ":" ..
				tostring(buf(offset+5,1):uint())
	end

	-- One OD record: OrgStop DstStop OrgTime(6) DstTime(6) RemainingNum
	-- RecordNum, then RecordNum x (TicketID, count). Returns bytes consumed.
	local function list_od_record(buf, tree, offset)
		local pos = offset
		tree:add(buf(pos,1),   "  OrgStopID:" .. buf(pos,1):uint())
		tree:add(buf(pos+1,1), "  DstStopID:" .. buf(pos+1,1):uint())
		tree:add(buf(pos+2,6), "  OrgODTime:" .. od_time_str(buf, pos+2))
		tree:add(buf(pos+8,6), "  DstODTime:" .. od_time_str(buf, pos+8))
		tree:add(buf(pos+14,1),"  RemainingNum:" .. buf(pos+14,1):uint())
		local recordNum = buf(pos+15,1):uint()
		tree:add(buf(pos+15,1),"  RecordNum:" .. recordNum)
		pos = pos + 16
		for i = 0, recordNum-1 do
			pos = pos + i*2
			tree:add(buf(pos,1),  "    TicketID[" .. i .. "]:" .. buf(pos,1):uint())
			tree:add(buf(pos+1,1),"    TickedNum[" .. i .. "]:" .. buf(pos+1,1):uint())
		end
		return 16 + recordNum*2
	end

	local function list_od_records(buf, tree, count, offset)
		if count <= 0 then return end
		local pos = offset
		for _ = 1, count do
			pos = pos + list_od_record(buf, tree, pos)
		end
	end

	------------------------------------------------------------------------
	-- Per-message dissectors (dispatched by MsgID; offsets absolute)
	------------------------------------------------------------------------

	-- 0x00 Reg
	local function msg_register(buf, pkt, tree)
		decode_monitor2(buf, pkt, tree, 20)
		tree:add(f_IMSI, buf(50,15))
		tree:add(f_IMEI, buf(65,15))
		local out = {
			mkStrField("IMSI", getBufStr(buf,50,15)),
			mkStrField("IMEI", getBufStr(buf,65,15))
		}
		show_num(out, tree, buf(80,1), "Vendor:", "Vendor", buf(80,1):uint())
		tree:add(f_OBUVersion, buf(81,8))
		out[#out+1] = mkStrField("OBUVer", getBufStr(buf,81,8))
		show_str(out, tree, buf(89,1), "RegType:",        "RegType",      table2Value(REG_TYPE,       buf(89,1):uint()))
		show_str(out, tree, buf(90,1), "DriverID Mode:",  "DriverIDMode", table2Value(DRIVER_ID_TYPE, buf(90,1):uint()))
		show_num(out, tree, buf(91,1), "FileNumber:",     "FileNumber",   buf(91,1):uint())
		-- Filenames: FileNum x 10-byte entries @92 (decode if ever needed)
		emit_info(pkt, out)
	end

	-- 0x01 Reg_A
	local function msg_register_ack(buf, pkt, tree)
		tree:add(buf(20,1),"Result: " .. buf(20,1):uint())
		-- NOTE: schedule description looks up byte 20 (Result), not 21 -- kept as-is
		tree:add(buf(21,1),"Schedule: " .. buf(21,1):uint() .. table2Value(SCHEDULE, buf(20,1):uint()))
		tree:add_le(f_routeid, buf(22,2):uint())
		tree:add(buf(24,1),"Route Dir:" .. buf(24,1):uint())
		tree:add(buf(25,1),"Route Branch:" .. buf(25,1):uint())
		emit_info(pkt, {
			mkStrField("Result", buf(20,1):uint()),
			mkStrField("Schedule", buf(21,1):uint() .. table2Value(SCHEDULE, buf(20,1):uint())),
			mkNumField("Route", buf(22,2):le_uint()),
			mkNumField("RouteDir", buf(24,1):uint()),
			mkStrField("RouteBranch", route_branch_str(buf,25)) --todo: branch=0x00?
		})
	end

	-- 0x02 RouteUpd (route change)
	local function msg_route_change(buf, pkt, tree)
		tree:add_le(f_routeid, buf(20,2))
		tree:add(buf(22,1),"Route Dir:" .. buf(22,1):uint())
		tree:add(buf(23,1),"Route Branch:" .. buf(23,1):uint())
		emit_info(pkt, {
			mkNumField("Route", buf(20,2):le_uint()),
			mkNumField("RouteDir", buf(22,1):uint()),
			mkStrField("RouteBranch", route_branch_str(buf,23))
		})
	end

	local function msg_no_body(buf, pkt, tree) end -- acks / undecoded: 0x03 05 07 09 0B 29 F1 F3

	-- 0x04 GPS: Count x MonitorStruct1
	local function msg_gps(buf, pkt, tree)
		pkt.cols.info:append(table_concat_sep)
		local count = buf(20,1):uint()
		local objs = {}
		for i = 0, count-1 do
			local parts = decode_monitor1(buf, tree, 22 + i * MONITOR1_LEN)
			objs[#objs+1] = '{'..table.concat(parts, table_concat_sep)..'}'
		end
		pkt.cols.info:append(mkNumField('GPS','['..table.concat(objs, table_concat_sep) ..']'))
	end

	-- 0x08 Evt
	local function msg_event(buf, pkt, tree)
		tree:add_le(f_EventType, buf(20,2))
		tree:add_le(f_routeid, buf(22,2))
		tree:add(buf(24,1),"Route Dir:" .. buf(24,1):uint())
		tree:add(buf(25,1),"Route Branch:" .. buf(25,1):uint())
		emit_info(pkt, {
			mkStrField("EvtType", table2Value(EVENT_TYPE, buf(20,2):le_uint())),
			mkNumField("Route", buf(22,2):le_uint()),
			mkNumField("RouteDir", buf(24,1):uint()),
			mkStrField("RouteBranch", route_branch_str(buf,25))
		})

		decode_monitor2(buf, pkt, tree, 26)

		local handler = EVENT_DISSECTOR[buf(20,2):le_uint()]
		if handler ~= nil then
			handler(buf, pkt, tree)
		else
			pkt.cols.info:append(',"RAW":"')
			pkt.cols.info:append(tostring(buf(EVT_PAYLOAD_OFF, buf:len() - EVT_PAYLOAD_OFF)) .. '"')
		end
	end

	-- 0x0A ACC (ignition on/off report)
	local function msg_acc_off(buf, pkt, tree)
		decode_monitor2(buf, pkt, tree, 20)
		local out = {}
		show_num(out, tree, buf(50,2), "PSDReconnect:", "PSDReconnect", buf(50,2):le_uint())
		show_num(out, tree, buf(52,1), "PacketRatio:",  "PacketRatio",  buf(52,1):uint())
		show_num(out, tree, buf(53,1), "GPSRatio:",     "GPSRatio",     buf(53,1):uint())
		emit_info(pkt, out)
	end

	-- 0xF0 Malfunc
	local function msg_malfunc(buf, pkt, tree)
		local out = {}
		show_str(out, tree, buf(20,1), "Malfunction Module:", "MalfDevice", table2Value(MAL_MODULE, buf(20,1):uint()))
		show_str(out, tree, buf(21,1), "Malfunction Code:",   "MalfReason", table2Value(MAL_STATUS, buf(21,1):uint()))
		emit_info(pkt, out)
	end

	-- 0xF2 OD (origin/destination ticket report)
	local function msg_od(buf, pkt, tree)
		tree:add_le(f_routeid, buf(20,2))
		tree:add(buf(22,1),"Route Dir:" .. buf(22,1):uint())
		tree:add(buf(23,1),"Route Branch:" .. buf(23,1):uint())
		pkt.cols.info:append(", Route:" .. tostring(buf(20,2):le_uint()) .. tostring(buf(22,1):uint()) .. buf(23,1):string())
		local odCount = buf(24,1):uint()
		tree:add(buf(24,1),"ODRecord:" .. odCount)
		tree:add(buf(25,1),"Reserved")
		list_od_records(buf, tree, odCount, 26)
	end

	-- 0x28 Debug: free-form ASCII; "@BG" vendor reports partially decoded.
	-- Layout hints for the "@BO" variant: route@48(5) CarNo@35(6) StopNo@54(2)
	local function msg_debug(buf, pkt, tree)
		local len = buf(18,2):le_uint()
		tree:add(f_debugRoute, buf(20,len))
		emit_info(pkt, { mkStrField("DebugInfo", buf(20,len):string()) })

		local first3 = getBufStr(buf,20,3)
		if first3 == "@BG" then
			-- @BG <comp/field> ... <route> ... <lat> <lng> <speed> <azimuth> <dir>
			tree:add(buf(23,4),"Company/field:" .. getBufStr(buf,23,4))
			tree:add(buf(32,6),"Route:" .. getBufStr(buf,32,6))

			-- ddmm.mmmmm ASCII -> decimal degrees
			local lat = getBufStr(buf,45,9) / 1000000
			local lng = getBufStr(buf,54,8) / 1000000
			lat = math.floor(lat) + (lat % 1) / 0.6
			lng = math.floor(lng) + (lng % 1) / 0.6

			tree:add(buf(45,9),"Lat:" .. lat)
			tree:add(buf(54,8),"Lng:" .. lng)
			tree:add(buf(62,3),"Speed:" .. getBufStr(buf,62,3))
			tree:add(buf(65,3),"Azimuth:" .. getBufStr(buf,65,3))
			tree:add(buf(68,3),"Dir/Login/Event:" .. getBufStr(buf,68,3))
		end
	end

	local MSG_DISSECTOR = {
		[0x00] = msg_register,
		[0x01] = msg_register_ack,
		[0x02] = msg_route_change,
		[0x03] = msg_no_body,
		[0x04] = msg_gps,
		[0x05] = msg_no_body,
		[0x06] = msg_no_body, -- SendMsg: not decoded
		[0x07] = msg_no_body,
		[0x08] = msg_event,
		[0x09] = msg_no_body,
		[0x0A] = msg_acc_off,
		[0x0B] = msg_no_body,
		[0x28] = msg_debug,
		[0x29] = msg_no_body,
		[0xF0] = msg_malfunc,
		[0xF1] = msg_no_body,
		[0xF2] = msg_od,
		[0xF3] = msg_no_body
	}

	------------------------------------------------------------------------
	-- Common header + entry points
	------------------------------------------------------------------------

	-- Decode the 20-byte common header into the tree + Info column.
	local function decode_header(buf, pkt, tree)
		tree:add(buf(0,4), "ProtocolID: " .. getBufStr(buf,0,4))
		tree:add(buf(4,1), "protocol Version:" .. buf(4,1):uint())
		tree:add(f_msgID, buf(5,1))
		tree:add(f_CustID, buf(6,2))
		tree:add(f_CarID, buf(8,2))
		tree:add(buf(10,1), "StorageID: " .. buf(10,1):uint())
		tree:add(f_DriverID, buf(11,4))
		tree:add_le(f_seq, buf(15,2))
		tree:add(buf(17,1), "Reserved")
		tree:add(buf(18,2), "Length: " .. buf(18,2):le_uint())

		-- CustID/CarID as 4 hex digits, high byte first
		local custID = string.format("%02x%02x", buf(6,1):uint(), buf(7,1):uint())
		local carID  = string.format("%02x%02x", buf(8,1):uint(), buf(9,1):uint())
		local typeName = MSGID[buf(5,1):uint()]
		if typeName == nil then typeName = tostring(buf(5,1)) end

		pkt.cols.info:append(table.concat({
			mkStrField('TY', typeName),
			mkStrField('CUST', custID),
			mkStrField('BUS', carID),
			mkNumField('No', buf(15,2):le_uint()),
			mkNumField('StorageID', buf(10,1):uint()),
			mkStrField('Driver', buf(11,4):le_uint())
		}, table_concat_sep))
	end

	-- Decode one TTIA packet; returns false when too short to be one.
	local function dissect_ttia(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < HDR_LEN then return false end

		local t = root:add(p_TTIAVT, buf(0, buf_len))
		pkt.cols.protocol = "TTIAVT"

		if l_outputJSON and l_cee then
			pkt.cols.info = '@cee: {'
		elseif l_outputJSON then
			pkt.cols.info = '{'
		else
			pkt.cols.info = ''
		end
		decode_header(buf, pkt, t)

		if buf_len > HDR_LEN then
			local handler = MSG_DISSECTOR[buf(5,1):uint()]
			if handler ~= nil then
				handler(buf, pkt, t)
			else
				pkt.cols.info:append(',"RAW":"')
				pkt.cols.info:append(tostring(buf(HDR_LEN, buf_len - HDR_LEN)) .. '"')
			end
		end

		if l_outputJSON then
			local ms, frac = math.modf(pkt.abs_ts * 1000)
			pkt.cols.info:append(table_concat_sep .. mkNumField('tm',ms) .. table_concat_sep)
			pkt.cols.info:append(mkStrField('src',tostring(pkt.src)) .. table_concat_sep)
			pkt.cols.info:append(mkNumField('sport',pkt.src_port) .. table_concat_sep)
			pkt.cols.info:append(mkStrField('dst',tostring(pkt.dst)) .. table_concat_sep)
			pkt.cols.info:append(mkNumField('dport',pkt.dst_port))
			pkt.cols.info:append('}')
		end
		return true
	end

	local data_dis = Dissector.get("data")

	function p_TTIAVT.dissector(buf, pkt, root)
		if not dissect_ttia(buf, pkt, root) then
			data_dis:call(buf, pkt, root)
		end
	end

	DissectorTable.get("udp.port"):add(3806, p_TTIAVT)

end
