
# nsmcli
Python app for Basic Operations with Network Security Platform

## Usage
nsmcli.py [-h] -u USER -p PASSWORD -nsm NSM_IP [-get_sensors][-get_qhosts][-sensor SENSOR_NAME][-i IP_ADDRESS][-quarantine][-remove]
	      [-t {15,30,45,60,240,480,720,960,999}][--version]

## Examples of usage

1)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -get_sensors
    
    Name          ID        Model     Sensor IP       SW Ver      Sigset Ver  Active
    ********************************************************************************
    M2750-4pocs   1001      M-2750    192.168.0.203   7.5.3.16    7.6.14.9    1     
    
2)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -get_qhosts

    Quarantined hosts for M2750-4pocs

    IP Address    Time (Milliseconds)
    *********************************
    123.1.1.1     1375816982000      
    124.1.1.1     1375818027000
    
3)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -quarantine
    
    Sensor  M2750-4pocs IP 10.10.10.100 quarantine for FIFTEEN_MINUTES 

4)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -remove
    
    Sensor  M2750-4pocs IP 10.10.10.100 removed from quarantine
    
5)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.101 -quarantine -t 45 -get_sensors -get_qhosts -sensor M2750-4pocs
    
    Sensor  M2750-4pocs IP 10.10.10.101 quarantine for FORTYFIVE_MINUTES
     
    Name          ID        Model     Sensor IP       SW Ver      Sigset Ver  Active
    ********************************************************************************
    M2750-4pocs   1001      M-2750    192.168.0.203   7.5.3.16    7.6.14.9    1     

    Quarantined hosts for M2750-4pocs

    IP Address    Time (Milliseconds)
    *********************************
    123.1.1.1     1375816982000      
    124.1.1.1     1375818027000      
    10.10.10.100  1375818561000      
    10.10.10.101  1375818608000
    
6)  nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -remove -get_sensors -get_qhosts -sensor M2750-4pocs

    Sensor  M2750-4pocs IP 10.10.10.100 removed from quarantine

    Name          ID        Model     Sensor IP       SW Ver      Sigset Ver  Active
    ********************************************************************************
    M2750-4pocs   1001      M-2750    192.168.0.203   7.5.3.16    7.6.14.9    1     

    Quarantined hosts for M2750-4pocs

    IP Address    Time (Milliseconds)
    *********************************
    123.1.1.1     1375816982000      
    124.1.1.1     1375818027000      
    10.10.10.101  1375818608000      
    10.10.10.102  1375818798000      
    10.10.10.103  1375818860000      

