# smart-home-firewall
Profile-based, multi-layer Smart Home firewall, based on NFTables &amp; NFQueue, supporting device interactions.

Research accepted at [IFIP Networking 2024](https://networking.ifip.org/2024/).

## Local compilation

Compile locally with:
```bash
./translate_profiles.sh
mkdir build bin
cd build
cmake ..
cmake --build .
```
or, more easily:
```bash
./translate_profiles.sh
./build.sh
```

## Cross-compilation for OpenWrt

We provide two Docker images to cross-compile for two OpenWrt targets:
- [TP-Link TL-WDR4900](https://openwrt.org/toh/tp-link/tl-wdr4900): https://hub.docker.com/r/fdekeers/openwrt_tl-wdr4900
- [Linksys WRT1200AC](https://openwrt.org/toh/linksys/wrt1200ac): https://hub.docker.com/r/fdekeers/openwrt_linksys-wrt1200ac

To pull either of them:
```bash
docker pull fdekeers/openwrt_tl-wdr4900
docker pull fdekeers/openwrt_linksys-wrt1200ac
```

To run cross-compilation with either image:
```bash
docker run --rm --mount type=bind,source="$(pwd)",target=/home/user/smart-home-firewall -e ROUTER=tl-wdr4900 fdekeers/openwrt_tl-wdr4900
docker run --rm --mount type=bind,source="$(pwd)",target=/home/user/smart-home-firewall -e ROUTER=linksys-wrt1200ac fdekeers/openwrt_linksys-wrt1200ac
```
