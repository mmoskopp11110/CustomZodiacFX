# Application Aware Switching with Zodiac FX

## Project Structure

```
├── README.MD          <- The top-level README for developers using this project.
├── report.pdf         <- Our report describing this work and the whole setup
├── Controller         <- The Ryu SDN controller.
├── Demo               <- A flask web application for demonstration of the project.
└── Firmware           <- The Zodiac FX firmware
    ├── README.md      <- Zodiac FX README/Instructions for building the firmware.
    ├── FirmwareBins   <- Custom firmware binaries ready to be flashed to the switch.
    └── FirmwareSrc    <- Contains different versions of the ZodiacFX firmware source code.
        ├── 0.85       <- The original ZodiacFX firmware in version 0.85.
        ├── A          <- Custom firmware A (without http server, OF 1.3 and VLAN matching/actions).
        ├── B          <- Custom firmware B (without port/flow/table stats).
        └── C          <- Custom firmware C (first matching flow instead of highest priority flow).
```

## Required Tools/Software

* extraputty (http://www.extraputty.com/) for flashing custom firmware via XMODEM
* HxD Hex-Editor (https://mh-nexus.de/de/hxd/) for editing custom firmware builds
* Atmel SAM-BA In-system Programmer (https://www.microchip.com/DevelopmentTools/ProductDetails/Atmel%20SAM-BA%20In-system%20Programmer) for resetting the firmware
* Atmel Studio 7 (https://www.microchip.com/mplab/avr-support/atmel-studio-7) for building the firmware
* iperf3 (https://iperf.fr/) for the throughput measurements