# External Aircrack-ng companion

The companion makes live Wi-Fi possible by running genuine Aircrack-ng on a Raspberry Pi or other Linux computer. The Flipper Zero supplies the controls and display. A Wi-Fi adapter whose Linux driver supports monitor mode is required; the stock Flipper radios cannot replace it.

## Hardware

- Raspberry Pi or Linux computer
- Dedicated USB Wi-Fi adapter with Linux monitor-mode support
- Three female-to-female jumper wires
- Flipper Zero with Aircrack-ng FZ 1.0.3

Both devices use 3.3 V UART. Do not connect a 5 V UART signal, and do not connect either device's power pin to the other. Connect:

| Flipper Zero | Raspberry Pi 40-pin header |
|---|---|
| Pin 13, USART TX | Physical pin 10, GPIO15/RX |
| Pin 14, USART RX | Physical pin 8, GPIO14/TX |
| Pin 11, GND | Physical pin 6, GND |

TX and RX are crossed. The Flipper protocol uses USART pins 13/14 and temporarily disables the firmware expansion listener while the external screen is open.

## Prepare Raspberry Pi OS

Use only on networks and channels you own or are authorized to assess.

1. Enable UART hardware and disable the serial login console:

   ```sh
   sudo raspi-config
   ```

   Select **Interface Options -> Serial Port**, answer **No** to a login shell and **Yes** to serial hardware, then reboot.

2. Install the genuine tools and Python support:

   ```sh
   sudo apt update
   sudo apt install aircrack-ng iw python3-venv
   ```

3. Copy the repository's `companion` directory to `/opt/aircrack-fz`, then create an isolated environment:

   ```sh
   cd /opt/aircrack-fz
   python3 -m venv venv
   ./venv/bin/pip install -r requirements.txt
   sudo mkdir -p /var/lib/aircrack-fz/captures
   ```

4. Identify the dedicated adapter:

   ```sh
   iw dev
   ```

5. Create monitor mode using Aircrack-ng. Replace `wlan1` with the dedicated adapter:

   ```sh
   sudo airmon-ng check
   sudo airmon-ng start wlan1
   iw dev
   ```

   Use the monitor interface reported by `airmon-ng`, commonly `wlan1mon`. Stopping conflicting processes with `airmon-ng check kill` can disconnect the Pi, so do that only from a local console and only when necessary.

## Run and test

With the three UART wires connected, run:

```sh
sudo /opt/aircrack-fz/venv/bin/python /opt/aircrack-fz/aircrack_fz_bridge.py \
  --interface wlan1mon --serial /dev/serial0 --baud 115200
```

On the Flipper, set **Settings -> External baud -> 115200**, choose a channel, and open **External Aircrack-ng**. It should change from `Waiting for Pi` to the real version, interface, and `IDLE`. Press **OK** to capture and **OK** again to stop.

The bridge accepts only the fixed `HELLO`, `STATUS`, `START channel`, and `STOP` protocol commands. It does not pass shell text from UART. Capture names use UTC time and are stored under `/var/lib/aircrack-fz/captures` by default. Retrieve a capture from your PC with `scp`, or copy it to the Flipper microSD card and inspect it through **Offline Aircrack Analysis**.

For automatic startup, edit the interface in `aircrack-fz-bridge.service.example`, install it as `/etc/systemd/system/aircrack-fz-bridge.service`, then enable it with:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now aircrack-fz-bridge.service
```

## Honest validation status

The Flipper application, protocol parser, and build can be tested without a Pi. End-to-end UART, adapter, and monitor-mode behavior requires the actual Raspberry Pi and adapter and is not marked as hardware-validated until those devices are available.

Official references: [Flipper expansion UART mapping](https://developer.flipper.net/flipperzero/doxygen/expansion_protocol.html) and [Raspberry Pi UART configuration](https://www.raspberrypi.com/documentation/computers/configuration.html).
