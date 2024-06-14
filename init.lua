---@alias target (integer|false)[]
---@alias generator target|(fun(self: Patch, location: integer): target)

---@class (exact) Range
---@field first integer
---@field last integer

---@class (exact) Patch
---@field target target
---@field new generator?
---@field condition string
---@field range Range
---@field location integer? this is set when we find it at runtime.
---@field before integer[]?
---@field after integer[]?
---@field enabled boolean?
---@field data table<any, any>?

local debugging = ModSettingGet("noita_engine_patcher.debug") == true
local early_logs = ""
local function log(...)
	for _, v in ipairs({ ... }) do
		early_logs = early_logs .. tostring(v) .. " "
	end
	early_logs = early_logs .. "\n"
end

local io = require("io")
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
void* VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
int memcmp(const void *buffer1, const void *buffer2, size_t count);
]])

local info = ffi.new("SYSTEM_INFO")
ffi.C.GetSystemInfo(info)
---@diagnostic disable-next-line: undefined-field
local page_size = info.dwPageSize

local VirtualProtect = ffi.C.VirtualProtect

---@param values any[]
---@param count integer
---@return table
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
---@param cap integer
---@return integer?
local function find_in_page(page_start, pattern, pattern_size, cap)
	local original = ffi.new("int[1]") -- malloc 4 bytes
	VirtualProtect(ffi.cast("void*", page_start), page_size, 0x40, original) -- change page protection
	local other = ffi.new("int[1]") -- malloc 4 bytes
	if page_start + page_size < cap then
		VirtualProtect(ffi.cast("void*", page_start + page_size), page_size, 0x40, other) -- change page protection
	end
	for o = 0, page_size - 1 do
		if o + page_start + pattern_size > cap then
			return nil
		end
		local new = ffi.cast("char*", o + page_start)
		local eq = true
		for k, v in ipairs(pattern) do
			if v and ffi.cast("char", v) ~= new[k - 1] then
				eq = false
				break
			end
		end
		if eq then
			return o + page_start
		end
	end
	if other then
		VirtualProtect(ffi.cast("void*", page_start + page_size), page_size, other[0], other) -- change page protection
	end
	VirtualProtect(ffi.cast("void*", page_start), page_size, original[0], original) -- restore page protection
end

---@param page_start integer
---@param page_end integer
---@param base target
---@return integer?
local function find_in_page_range(page_start, page_end, base)
	local len = #base
	for page = page_start, page_end, page_size do
		local res = find_in_page(page, base, len, page_end)
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
	{
		-- stylua: ignore start
		target = {0x8b, 0x0d, false, false, false, false,
		0xb8, 0xab, 0xaa, 0xaa, 0x2a, 0x2b, 0x0d, false, false, false, false,
		0xf7, 0xe9, 0xc1, 0xfa, 0x04, 0x8b, 0xc2, 0xc1, 0xe8, 0x1f, 0x03, 0xc2, 0x83, 0xf8, 0x01, 0x76, false,
		0xe8, false, false, false, false, 0xa1, false, false, false, false, 0xc6, 0x80, 0x20, 0x01, 0x00, 0x00,
		0x01, },
		-- stylua: ignore end
		new = join(repeat_table({ false }, 50), { 0x00 }),
		condition = "mods",
		range = functions,
	},
	{
		-- stylua: ignore start
		target = {
		0xe8, false, false, false, false,
		0x84, 0xc0,
		false, false, false, false, false, false,
		0x83, 0xbd, 0xbc, 0xfc, 0xff, 0xff, 0x01,
		0x7c, false,
		0x8b, 0x85, 0x4c, 0xfe, 0xff, 0xff,
		0x85, 0xc0,
		0x7e, false,
		0x39, 0x85, 0xf4, 0xfb, 0xff, 0xff,
		0x7c, false,
		0xb3, 0x01,
		0xeb, false,
		0x32, 0xdb, 0x68, },
		-- stylua: ignore end
		new = join(repeat_table({ false }, 7), repeat_table(NOP, 6), repeat_table({ false }, 34)),
		condition = "mods",
		range = functions,
	},
	{
		-- stylua: ignore start
		target = { 0x84, 0xc0, 0x8b, 0x44, 0x24, 0x44, false, 0x26, 0xf2, 0x0f, 0x10, 0x40, 0x50, 0xf2, 0x0f, 0x59, 0x05, false, false, false, false, 0xf2, 0x0f, 0x10, 0x48, 0x48, 0x66, 0x0f, 0x2f, 0xc8, 0x76, 0x0e, 0x66, 0x0f, 0x5a, 0xc1, 0xf3, 0x0f, 0x59, 0x05, false, false, false, false, 0xeb, 0x09, 0xf2, 0x0f, 0x10, 0x40, 0x48, 0x66, 0x0f, 0x5a, 0xc0 },
		--stylua: ignore end
		new = function(self, location)
			if not self.data then
				self.data = {}
			end
			---@type ffi.cdata*
			self.data.memory = ffi.C.VirtualAlloc(nil, 8, 0x3000, 0x40)
			log("freezer")
			log(self.data.memory)
			local float_writer = ffi.cast("float *", self.data.memory)
			local addr = tonumber(ffi.cast("int", float_writer)) or 0
			float_writer[0] = 0.75
			float_writer[1] = 5.0
			local bytes_75 = {}
			local bytes_5 = {}
			for i = 1, 4 do
				bytes_75[i] = bit.band(bit.rshift(addr, (i - 1) * 8), 0xFF)
				bytes_5[i] = bit.band(bit.rshift(addr + 4, (i - 1) * 8), 0xFF)
			end
			return join({
				0x84,
				0xC0,
				0x8B,
				0x44,
				0x24,
				0x44,
				0xF3,
				0x0F,
				0x10,
				0x44,
				0x24,
				0x18,
				0x75,
				0x13,
				0xF2,
				0x0F,
				0x10,
				0x40,
				0x50,
				0x66,
				0x0F,
				0x5A,
				0xC0,
				0xF3,
				0x0F,
				0x59,
				0x05,
			}, bytes_75, { 0xEB, 0x08, 0xF3, 0x0F, 0x59, 0x05 }, bytes_5, repeat_table(NOP, 14))
		end,
		--join({ 0x84, 0xC0, 0x8B, 0x44, 0x24, 0x44, 0xF3, 0x0F, 0x10, 0x44, 0x24, 0x18, 0x75, 0x13, 0xF2, 0x0F, 0x10, 0x40, 0x50, 0x66, 0x0F, 0x5A, 0xC0, 0xF3, 0x0F, 0x59, 0x05, 0xEC, 0x14, 0x05, 0x01, 0xEB, 0x08, 0xF3, 0x0F, 0x59, 0x05, 0xAC, 0x05, 0x15, 0x01},
		--repeat_table(NOP, 14)), -- from freeze_melee.asm
		condition = "freeze_melee",
		range = functions,
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

---@param patch Patch
local function get_patch_addr(patch)
	if patch.location then
		return patch.location
	end
	if patch.new == nil then
		patch.new = repeat_table(NOP, #patch.target)
	end
	if type(patch.new) == "table" then
		if #patch.target ~= #patch.new then
			error(
				"patch "
					.. patch.condition
					.. " has mismatched target of "
					.. #patch.target
					.. " and new of "
					.. #patch.new
			)
		end
	end
	local start = find_in_page_range(patch.range.first, patch.range.last, patch.target)
	if not start then
		error("patch " .. patch.condition .. " not found")
	end
	log(ffi.cast("char*", start), patch.condition)
	return start
end

---@param patch Patch
---@param page_end integer
local function apply_patch_state(patch, page_end)
	local location = assert(patch.location)
	local ptr = ffi.cast("char*", patch.location)
	local enabled = ModSettingGet("noita_engine_patcher." .. patch.condition) == true

	local original = ffi.new("int[1]") -- malloc 4 bytes
	VirtualProtect(ptr, #patch.target, 0x40, original) -- change page protection
	local other = ffi.new("int[1]") -- malloc 4 bytes
	if location + #patch.target < page_end then
		VirtualProtect(ffi.cast("void*", location + #patch.target), #patch.target, 0x40, other) -- change page protection
	end
	---@type target
	local new
	if type(patch.new) == "function" then
		new = patch:new(patch.location)
	else
		---@diagnostic disable-next-line: cast-local-type
		new = patch.new
	end
	if #new ~= #patch.target then
		error(
			"invalid function patch length generated for "
				.. patch.condition
				.. "\ngot: "
				.. #new
				.. " expected: "
				.. #patch.target
		)
	end
	---@cast new target

	if not patch.before then
		patch.before = {}
		for i = 0, #new - 1 do
			patch.before[i + 1] = ptr[i]
		end
	end
	if enabled and not patch.after then
		patch.after = {}
		for i = 1, #new do
			patch.after[i] = new[i] and new[i] or ptr[i - 1]
		end
	end
	if patch.enabled == enabled then
		return
	end
	patch.enabled = enabled
	local bytes = assert(enabled and patch.after or patch.before)

	local new_hex = {}
	local binary = {}
	for i = 0, #new - 1 do
		ptr[i] = ffi.new("char", bytes[i + 1])
		new_hex[i + 1] = to_hex_byte(bytes[i + 1])
		binary[i + 1] = bytes[i + 1]
	end
	log(unpack(new_hex))
	for k, byte in ipairs(binary) do
		byte = (byte < 0 and (256 + byte) or byte)
		binary[k] = byte
	end
	if debugging then
		local tmp_file = "data/noita_engine_patcher_asm"
		local write_proc = assert(io.open(tmp_file, "wb"))
		local byte_str = string.char(unpack(binary))
		write_proc:write(byte_str)
		write_proc:flush()
		write_proc:close()
		local asm_proc = assert(io.popen("mods/noita_engine_patcher/ndisasm.exe -u " .. tmp_file, "r"))
		---@type string
		local asm = assert(asm_proc:read("*a"))
		asm_proc:close()
		log(asm)
	end

	if other then
		VirtualProtect(ffi.cast("void*", location + #patch.target), #patch.target, other[0], other) -- change page protection
	end
	VirtualProtect(ptr, #patch.target, original[0], original) -- restore page protection
end

local function apply_patches()
	for _, patch in ipairs(patches) do
		patch.location = get_patch_addr(patch)
		apply_patch_state(patch, patch.range.last)
	end
end

function OnPausedChanged(paused)
	if not paused then
		apply_patches()
	end
end

if debugging then
	io.popen("Z:\\home\\nathan\\Documents\\misc_tools\\CE\\Cheat_Engine.exe")
	log(pcall(apply_patches))
else
	apply_patches()
end

function OnPlayerSpawned()
	print(early_logs)
end
