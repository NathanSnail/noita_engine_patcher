# Noita Engine Patcher
Contains various engine patches for Noita to change certain features

## Features

* Stats in frames: Display cast delay and recharge time stats in frames instead of seconds.
* Disable mod restrictions: Disable all mod restrictions, note that wand ghosts that get created with spell mods active will not load correctly if the spell mods are removed.
* Debug logs: For testing, not useful for normal use.
* Freeze melee nerf: Freeze melees now do 0.75x of max hp for enemies and 5x base damage on player.
* Eyes render as circles: Change the eyes to render like the Paha Silmä, requires disable mod restrictions to be enabled.
* Disable permanent poly: Prevents the permanent poly effect from chaotic polymorphing 85 times from happening.

## Install

### Download
Either:
* Press Code -> Download zip, unzip it and place it into your Noita mods folder so that the path looks like `Noita/mods/noita_engine_patcher/init.lua`. Note that the name matters.
* Run `git clone https://github.com/NathanSnail/noita_engine_patcher.git` inside your mods folder.

After downloading enable unsafe mods in game and enable the mod, then configure the patches you want in mod settings.
