dofile("data/scripts/lib/mod_settings.lua")

local mod_id = "noita_engine_patcher" -- This should match the name of your mod's folder.
mod_settings_version = 1 -- This is a magic global that can be used to migrate settings to new mod versions. call mod_settings_get_version() before mod_settings_update() to get the old value.

local function generate_setting(id, name)
	return {
		id = id,
		ui_name = name,
		value_default = false,
		ui_fn = function(mod_id, gui, in_main_menu, im_id, setting)
			GuiLayoutBeginHorizontal(gui, 0, 0)
			GuiText(gui, 0, 0, name .. ": ")
			local state = ModSettingGet(mod_id .. "." .. id) or false
			if GuiButton(gui, im_id, 0, 0, tostring(state)) then
				state = not state
				ModSettingSetNextValue(mod_id .. "." .. id, state, false)
				ModSettingSet(mod_id .. "." .. id, state)
			end
			GuiLayoutEnd(gui)
		end,
		scope = MOD_SETTING_SCOPE_RUNTIME,
	}
end

mod_settings = {
	generate_setting("frames", "Stats in frames"),
	generate_setting("mods", "Disable mod restrictions"),
	generate_setting("debug", "Debug logs"),
}

-- This function is called to ensure the correct setting values are visible to the game. your mod's settings don't work if you don't have a function like this defined in settings.lua.
function ModSettingsUpdate(init_scope)
	local old_version = mod_settings_get_version(mod_id) -- This can be used to migrate some settings between mod versions.
	mod_settings_update(mod_id, mod_settings, init_scope)
end

-- This function should return the number of visible setting UI elements.
-- Your mod's settings wont be visible in the mod settings menu if this function isn't defined correctly.
-- If your mod changes the displayed settings dynamically, you might need to implement custom logic for this function.
function ModSettingsGuiCount()
	return mod_settings_gui_count(mod_id, mod_settings)
end

-- This function is called to display the settings UI for this mod. your mod's settings wont be visible in the mod settings menu if this function isn't defined correctly.
function ModSettingsGui(gui, in_main_menu)
	mod_settings_gui(mod_id, mod_settings, gui, in_main_menu)
end
