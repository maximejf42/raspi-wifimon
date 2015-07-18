## Hardware
This runs on a Raspberry Pi Model B, although all the other models should work too.

I am using a $8 [WiFi dongle](http://www.dx.com/p/67532) from Dealextreme. It just works (tm) after pluggin into the RasPi. `lsusb` reports it as `Ralink Technology, Corp. RT5370 Wireless Adapter` with ID `148f:5370`.

## Installing Aircrack-ng on the Raspberry Pi
I followed this [blog post](http://blog.petrilopia.net/linux/raspberry-pi-install-aircrackng-suite/), however some additional packages (libnl-3-dev libnl-genl-3-dev iw ethtool) hat to be installed for it to work.

    sudo apt-get -y update
    sudo apt-get -y install libssl-dev libnl-3-dev libnl-genl-3-dev iw ethtool python-scapy tcpdump
    wget http://download.aircrack-ng.org/aircrack-ng-1.2-rc2.tar.gz
    tar -zxvf aircrack-ng-1.2-rc2.tar.gz
    cd aircrack-ng-1.2-rc2/
    make
    sudo make install
    sudo airodump-ng-oui-update

## Try out Airodump

    sudo airmon-ng start wlan0

In the output, look for `Interface`, it should read `wlan0mon` or `mon0`. You have to use for the following commands. If you see an error message, run it again.

Now, run `airodump-ng wlan0mon`. After some seconds, you should see a list of SSIDs in your environment. If this works, everything is ready!

To gain back normal WiFi functionality just run `sudo airmon-ng stop wlan0mon`.


Data to gather:

    Beacon Packets: (Type = 00, subtype = 0x8), SSID, AP Addr
    Data Packets: (Type = 10) Recv addr, Trsmt addr, Timestamp
