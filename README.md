# MDBrute
 
Brute-force memdatabase address search for RoM-Bot

## Compatibility
This tool was built for use with the Gameforge client.
It should function out-of-the-box for all client languages.

## To use
* Log into the game
* Run MDBrute.exe with **administrator privileges**.
* Wait a few minutes until the console window disappears.
* Open log.txt, scroll to the bottom for a list of found addresses
* Plug one of those into RoM-Bot's `addresses.lua` file for the value of `memdatabase.base`

#### What do I do if no results were found?
Try opening up `config.json` with a text editor. This file will be auto-created for you
when you run MDBrute if one does not already exist.

Try changing the values for `start_address` and `end_address` to cover a wider range of
addresses; the wider the range, the longer it will take, but better your chance at
finding matches.

## Configuration
| Config name   | Default      | Description |
|---------------|--------------|-------------|
| workers       | 8            | The number of threads to run the scan across. Leave this alone if you don't understand what this means |
| chunk_size    | "0x400"      | The range of addresses passed as a worker thread for processing. Leave this alone unless you know what you're doing |
| item_id       | 540000       | Any item/skill/etc. that we expect to find in the memory DB. |
| item_name     | ["Attack", "Angreifen", "Ataque", "Attaque", "Atak"] | Name, or array of names (for multiple language support) corresponding to the item_id; Used for verification. |
| start_address | "0x00630000" | The lower bounds of where to begin searching. This is an offset from Client.exe |
| end_address   | "0x00634000" | The upper bounds of where to begin searching. This is an offset from Client.exe |
| module_base_address | "0x400000" | The base address for Client.exe. Leave this alone unless you know what you're doing. |


## License
Public domain. Use it as you wish.