---@class (exact) Patch
---@field target integer[]
---@field new integer[]

---@type Patch[]
local patches = {
	target = { 0x0 },
}
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
---@param pattern ffi.cdata*
---@param pattern_size integer
---@return ffi.cdata*?
local function find_in_page(page_start, pattern, pattern_size)
	local original = ffi.new("int[1]") -- malloc 4 bytes
	VirtualProtect(ffi.cast("void*", page_start), page_size, 0x40, original) -- change page protection
	for o = 0, page_size - 1 - pattern_size do -- TODO: allow for searching for patterns that cross pages
		local new = ffi.cast("char*", o + page_start)
		local cmp = ffi.C.memcmp(new, pattern, pattern_size)
		if cmp == 0 then
			return new
		end
	end
	VirtualProtect(ffi.cast("void*", page_start), page_size, original[0], original) -- restore page protection
end

---@param page_start integer
---@param page_end integer
---@param base integer[]
---@return ffi.cdata*?
local function find_in_page_range(page_start, page_end, base)
	local len = #base
	local goal = ffi.new("char[" .. len .. "]", base)
	for page = page_start, page_end, page_size do
		local res = find_in_page(page, goal, len)
		if res then
			return res
		end
	end
end

local base = { 0xf3, 0x0f, 0x5e, 0x05, 0x50 }
function OnWorldPostUpdate()
	local v = find_in_page_range(0x00b50000, 0x00b60000, base)
	print(tostring(v))
end

