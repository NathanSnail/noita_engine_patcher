---@alias target (integer|boolean)[]

---@class (exact) Range
---@field first integer
---@field last integer

---@class (exact) Patch
---@field target target
---@field new integer[]?
---@field condition string
---@field range Range
---@field lua fun()?
---@field location ffi.cdata*? this is set when we find it at runtime.

local early_logs = ""
local function log(...)
	for _, v in ipairs({ ... }) do
		early_logs = early_logs .. tostring(v) .. " "
	end
	early_logs = early_logs .. "\n"
end

local io = require("io")
local os = require("os")
local ffi = require("ffi")
ffi.cdef([[
typedef int DWORD;
typedef short WORD;
typedef void* LPVOID;
typedef int* DWORD_PTR;

typedef struct _SYSTEM_INFO {
	union {
		DWORD dwOemId;
		struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	DWORD dwPageSize;
	LPVOID lpMinimumApplicationAddress;
	LPVOID lpMaximumApplicationAddress;
	DWORD_PTR dwActiveProcessorMask;
	DWORD dwNumberOfProcessors;
	DWORD dwProcessorType;
	DWORD dwAllocationGranularity;
	WORD wProcessorLevel;
	WORD wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

bool VirtualProtect(void* adress, size_t size, int new_protect, int* old_protect);
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
int memcmp(const void *buffer1, const void *buffer2, size_t count);
]])

local info = ffi.new("SYSTEM_INFO")
ffi.C.GetSystemInfo(info)
---@diagnostic disable-next-line: undefined-field
local page_size = info.dwPageSize

local VirtualProtect = ffi.C.VirtualProtect

local function repeat_table(values, count)
	local new = {}
	for _ = 1, count do
		for _, v in ipairs(values) do
			table.insert(new, v)
		end
	end
	return new
end

---@param page_start integer
---@param pattern target
---@param pattern_size integer
---@return ffi.cdata*?
local function find_in_page(page_start, pattern, pattern_size)
	local original = ffi.new("int[1]") -- malloc 4 bytes
	VirtualProtect(ffi.cast("void*", page_start), page_size, 0x40, original) -- change page protection
	for o = 0, page_size - 1 - pattern_size do
		local new = ffi.cast("char*", o + page_start)
		local eq = true
		for k, v in ipairs(pattern) do
			if v and ffi.cast("char", v) ~= new[k - 1] then
				eq = false
				break
			end
		end
		if eq then
			return new
		end
	end
	VirtualProtect(ffi.cast("void*", page_start), page_size, original[0], original) -- restore page protection
end

---@param page_start integer
---@param page_end integer
---@param base target
---@return ffi.cdata*?
local function find_in_page_range(page_start, page_end, base)
	local len = #base
	for page = page_start, page_end, page_size do
		local res = find_in_page(page, base, len)
		if res then
			return res
		end
	end
end

local function join(a, ...)
	for _, v in ipairs({ ... }) do
		for _, v2 in ipairs(v) do
			table.insert(a, v2)
		end
	end
	return a
end

local function add_translation(key, value)
	local translations = (ModTextFileGetContent("data/translations/common.csv") .. "\n")
		:gsub("\r", "")
		:gsub("\n\n+", "\n")
	translations = translations .. key .. "," .. value .. ",,,,,,,,,,,,,\n"
	ModTextFileSetContent("data/translations/common.csv", translations)
end
add_translation("patcher_frames", "$0f")

local functions = { first = 0x00401000, last = 0x00f05000 }
local data = { first = 0x00f05000, last = 0x0122e000 }

local NOP = { 0x90 }

-- cool feature: nil -> NOP correct length
---@type Patch[]
local patches = {
	{
		-- stylua: ignore start
		target = { 0x66, 0x0f, 0x6e, 0xc2, 0xba, 0x02,
		0x00, 0x00, 0x00, 0x0f, 0x5b, 0xc0, 0x56, 0x8b, 0xf1, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00,
		0xf3, 0x0f, 0x5e, 0x05, false, false, false, false, },
		-- stylua: ignore end
		new = join({ false, false, false, false, false, 0x00 }, repeat_table({ false }, 16), repeat_table(NOP, 8)),
		condition = "frames",
		range = functions,
	},
	{
		-- stylua: ignore start 
		target = { 0x24, 0x69, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x00, },
		new =    { 0x24, 0x70, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x5f, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, },
		-- stylua: ignore end
		condition = "frames",
		range = data,
	},
}

local function to_hex_byte(v)
	v = (v < 0 and (256 + v) or v)
	local str = string.format("%x", v)
	if str:len() == 1 then
		str = "0" .. str
	end
	return str
end

local debugging = true
local function apply_patches()
	for _, v in ipairs(patches) do
		if v.new == nil then
			v.new = repeat_table(NOP, #v.target)
		end
		if #v.target ~= #v.new then
			error("patch " .. v.condition .. " has mismatched target of " .. #v.target .. " and new of " .. #v.new)
		end
		local start = find_in_page_range(v.range.first, v.range.last, v.target)
		if not start then
			error("patch " .. v.condition .. " not found")
		end
		log(start, v.condition)
		local new_hex = {}
		local binary = {}
		for i = 0, #v.new - 1 do
			if v.new[i + 1] then
				start[i] = ffi.new("char", v.new[i + 1])
			end
			new_hex[i + 1] = to_hex_byte(start[i])
			binary[i + 1] = start[i]
		end
		log(unpack(new_hex))
		for k, byte in ipairs(binary) do
			byte = (byte < 0 and (256 + byte) or byte)
			binary[k] = byte
		end
		if debugging then
			local tmp_file = "data/noita_engine_patcher_asm"
			local write_proc = assert(io.open(tmp_file, "wb"))
			local bytes = string.char(unpack(binary))
			write_proc:write(bytes)
			write_proc:flush()
			write_proc:close()
			local asm_proc = assert(io.popen("mods/noita_engine_patcher/ndisasm.exe -u " .. tmp_file, "r"))
			---@type string
			local asm = assert(asm_proc:read("*a"))
			asm_proc:close()
			log(asm)
		end
	end
end

apply_patches()
function OnWorldPostUpdate() end
function OnPlayerSpawned()
	print(early_logs)
end
