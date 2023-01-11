# MachineRecon
This is a shell script to help with gaining initial foothold into a machine.

Citing nmapAutomator as source for idea on making automated reconnaissance script

https://github.com/21y4d/nmapAutomator

Author: ReconDeveloper

Currently in beta testing phase and not being distributed. The machinerecon.sh script should be used for educational, ctf, or ethical hacking.

#installation steps for Ubuntu

sudo apt install ldap-utils nmap smbclient smbmap snmp python3-pip knot-dnsutils curl git

#install impacket 

sudo pip3 install impacket

#install crackmapexec

sudo pip3 install crackmapexec

#install kerbrute 

curl https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -o kerbrute

sudo ln -s $(pwd)/kerbrute /usr/local/bin/

#install enum4linux-ng 

git clone https://github.com/cddmp/enum4linux-ng.git

sudo ln -s $(pwd)/enum4linux-ng/enum4linux-ng.py /usr/local/bin/

#install ffuf 

wget https://github.com/ffuf/ffuf/releases/download/v1.5.0/ffuf_1.5.0_linux_amd64.tar.gz

tar -xvf ffuf_1.5.0_linux_amd64.tar.gz

sudo ln -s $(pwd)/ffuf /usr/local/bin/


#install MachineRecon 

git clone https://github.com/ReconDeveloper/MachineRecon.git

sudo ln -s $(pwd)/MachineRecon/machinerecon.sh /usr/local/bin/
