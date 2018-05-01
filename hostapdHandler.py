import fileinput
import os
import sys
import subprocess
import threading
import time

class HostapdException(Exception):
    pass
    
# Note: time.time() depends on clock settings, not exact
class HostapdHandler():
    def __init__(self, wlan_device="wlan0", init_ssid="SmartAP", hostapd_conf_path = "/etc/hostapd/hostapd.conf"):
        self.last_restart_time = time.time()-1000  # TODO: - max_of_min_interval
        self.wlan_device = wlan_device
        self.hostapd_conf_path = hostapd_conf_path
        self.change_wifi_ssid(init_ssid)
        self.restart_hostapd()

    def restart_min_interval(self):
        """Return the minimum time (sec) to wait for the next restart.
        
        hostapd service cant be restarted too often.
        The default service limit is to allow 5 restarts in a 10sec period.
        For more info: man systemd.unit and man systemd.service
        """
        #NOTE: be carefull in future multithreading support
        min_interval = 2.8  # By default a value of 3 secs should be ok
        current_time = time.time()
        return current_time - self.last_restart_time + min_interval
        

    def check_hostapd_status(self):
        """Return True if the service is up and running.
        """
        # IF it was restarted 
        ok_status_condition = "(running)"
        # Check for hostapd statud
        args = "service hostapd status"
        try:
            bytes_output = subprocess.check_output(args, shell=True)
            str_output = str(bytes_output.decode("utf8"))
            # print(not ok_status_condition in str_output)
            if not ok_status_condition in str_output:
                raise HostapdException("Hostapd service is not running properly\n \
                Here is the 'service hostapd status' output:"+str_output)
                #Wrong configuration? Hostapd not started?
            return True
        except subprocess.CalledProcessError as e:
            # Return non zero status
            print(e.output)
            raise HostapdException("Check your hostapd installation and configuration.\n\
            Run: 'service hostapd status' for details")

    def restart_hostapd(self):
        """Always call this after updating the hostapd config file.
        
        return True if restart service is successful
        """
        try:
            hostapd_status = self.check_hostapd_status()
        except HostapdException as e:
            print(e)
        # 
        wait_time = self.restart_min_interval()
        if wait_time > 0:  
            # Wait if the time between now and the last restart is < min_interval
            time.sleep(self.restart_min_interval())
        rstatus = subprocess.call("service hostapd restart", shell=True)
        self.last_restart_time = time.time()
        return rstatus == 0
        

    def change_wifi_visibility(self, stealth = True):
        """Edit the hostapd config file and restart the service"""

        write_char = str(int(stealth))  # 1 if stealth=true
        for line in fileinput.input(self.hostapd_conf_path, inplace=True): 
            if "ignore_broadcast_ssid" in line:
                line = "ignore_broadcast_ssid="+write_char+"\n"
            if "interface" in line:
                line = "interface="+self.wlan_device+"\n"
            sys.stdout.write(line)  # same for print?
            #Dont print anything inside the for or it will be
            # written to config file
        self.restart_hostapd()

    def change_wifi_password(self, psk):
        """Edit the hostapd config file and restart the service"""

        #Edit the config file.
        for line in fileinput.input(self.hostapd_conf_path, inplace=True): 
            if "wpa_passphrase" in line:
                line = "wpa_passphrase="+psk+"\n"
            if "interface" in line:
                line = "interface="+self.wlan_device+"\n"
            sys.stdout.write(line)  # same for print?
            #Dont print anything inside the for or it will be
            # written ti config file
        self.restart_hostapd()
        
    def change_wifi_ssid(self, ssid):
        """Edit the hostapd config file and restart the service"""

        #nano /etc/hostapd/hostapd.conf
        
        """with f as open(hostapd_conf_path):
            config_file = f.readlines()
        config_dict = {}
        for line in config_file:
            (key, val) = line.split("=")
            config_dict[key] = val"""
            
        for line in fileinput.input(self.hostapd_conf_path, inplace=True): 
            if "ssid" in line:
                line = "ssid="+ssid+"\n"
            if "interface" in line:
                line = "interface="+self.wlan_device+"\n"
            sys.stdout.write(line)  # same for print?
        #Dont print anything inside the for or it will be
        # written ti config file
        self.restart_hostapd()

#change_wifi_password("wlan0", "abcdefghilmnopa")
#change_wifi_ssid("wlan0", "Testa")

#restart_hostapd()
