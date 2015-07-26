## Hardware
This runs on a Raspberry Pi Model B, although all the other models should work too.

I am using a $8 [WiFi dongle](http://www.dx.com/p/67532) from Dealextreme. It just works (tm) after pluggin into the RasPi. `lsusb` reports it as `Ralink Technology, Corp. RT5370 Wireless Adapter` with ID `148f:5370`.

Be sure to have an ethernet conneciton to your Raspberry Pi! During setup we will change the wlan device to monitor mode and thus lose the wifi connection. So you could lock out yourself if you SSH into it using WiFi (although a restart will fix it).

## System setup

    sudo apt-get -y update
    sudo apt-get -y install iw python-scapy tcpdumppython-dev
    sudo pip install rpio

    # add a monitor device

    # test if monitoring works
    sudo iw phy phy0 interface add mon0 type monitor
    sudo iw dev wlan0 del
    sudo ifconfig mon0 up
    sudo iw dev mon0 set channel 6

    # tcpdump should continuously list captured packages. Kill it with Ctrl-C.
    sudo tcpdump -i mon0 -n

    # teardown, back to normal wifi operation
    sudo iw dev mon0 del
    sudo iw phy phy0 interface add wlan0 type managed

## Install our script

    scp -r raspi-mon pi@<ip_of_your_pi>

On your Pi, add the following line to `/etc/rc.local`:

    sudo python /home/pi/raspi-mon/server.py &
