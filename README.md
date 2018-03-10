# Citrix PVS Sealing Automation – a little bit more

On so many customers I stumble about the last automation steps to seal their Master Images with Citrix Provisioning Services. If the customer has used the BDM-ISO it’s neacassary to switch the Storage Device ID (WriteCache ID 0, local Install ID 1) and insert the BDM-Boot-ISO, the vDisk must created first and the Master Target Device in the PVS Collection also. After you have optimize and seal your image, you must change the vDisk to shared Mode, select the right WriteCacheType and CacheSize, select the right Load Balancing and replicate this vDisk accross your PVS Servers.. 

The complete how-to can be read here http://eucweb.com/2017/06/23/citrix-pvs-sealing-automation/
