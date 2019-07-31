# Changes compared to Zodiac FX v0.85

* `src/flash.c` doubled firmware update timeout
* `src/main.c` removed http server
* `src/switch.c`, `src/openflow/*` removed OF 1.3 related code
* `src/openflow/of_helper.*`, `src/openflow/openflow_10.c` adapt to remove VLAN matching/action functionality 
* `src/command.c`, `src/config/config_zodiac.h` adapt to the changes above