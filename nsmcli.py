#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        nsmcli
# Purpose:     Use of the Network Security Manager API for basic operations like:
#                - Get the sensors managed by a Network Security Manager
#                - Get the quarantine list of hosts
#                - Blacklist an IP Address
#                - Remove an IP Address from quarantine
#
# Author:      Carlos Munoz (carlos_munoz@mcafee.com)
#
# Created:     08/06/2013
# Copyright:   (c) Carlos M 2013
#-------------------------------------------------------------------------------
#
#-------------------------------------------------------------------------------
# Version: V1.0
# Release control:
#                08/06/2013 - First release
#
#-------------------------------------------------------------------------------
import requests
import sys
import argparse

requests.packages.urllib3.disable_warnings()

class nsm(object):
    '''
    classdocs
    '''
    

    def __init__(self, nsmserver):
        '''
        
        Description: Constructor
        
        Input      : IP address of Network Security Manager
        
        Output     : No Output
        
        Use        : To be used as a public interface
        '''
        self.nsmserver  = nsmserver
        self.sessionheader = {}
        self.sensors_raw = {}
        self.sensors_id = []
        
    def connect(self, user, password):
        ''' 
        
        Description: Set a connection to Network Security Manager
        
        Input      : User name and password strings
        
        Output     : Session header + Error Control
        
        Use        : To be used as a public interface
        '''
        authheader = {
                      'Accept': 'application/vnd.nsm.v1.0+json',
                      'Content-Type': 'application/json',
                      'NSM-SDK-API': '%s'
                      % self.b64(user,password)
                      }
        r = self.request_connect('get', 'https://%s/sdkapi/session' % self.nsmserver, authheader)
        
        if r[0] == 1:
  
            response = self.transform(r[1])
        
            sessionheader =  {
                              'Accept': 'application/vnd.nsm.v1.0+json',
                              'Content-Type': 'application/json',
                              'NSM-SDK-API': '%s'
                              % self.b64(response['session'], response['userId'])
                              }
            self.sessionheader = sessionheader
            
            return (1,sessionheader)
            
        else:
               
            return r
         
    def disconnect(self):
        '''
        
        Description: Close the connection.
        
        Input      : No input
        
        Output     : Error control 
        
        Use        : To be used as a public interface
        '''
        
        r = self.request_connect('delete', 'https://%s/sdkapi/session' % self.nsmserver, self.sessionheader)
        
        if r[0] == 1:
            return (1,self.transform(r[1]))
        else:
            return r
                           
    def transform(self,r):
        ''' 
        
        Description: Transform the NSM-SDK-API output to a Python dictionary with ASCII values
        
        input      : Response object of NSM-SDK-API interface 
        
        Output     : Dictionary with NSM-SDK-API information transformed
        
        Use        : To be used internally in the class
        '''
        import unicodedata
        import ast
        
        string = unicodedata.normalize('NFKD', r.text).encode('ascii','ignore')
        return ast.literal_eval(string)    
    
    def b64(self,user,password):
        ''' 
        
        Description: Transform user name and password string into b64 format
        
        Input      : User name and password strings
        
        Output     : Base 64 string compose of username:password
        
        Use        : To be used internally in the class
        '''
        import base64
        authstring = user + ':' + password
        return base64.b64encode(authstring)
    
    def request_connect(self,optype,url,header,payload=''):
        '''
        
        Description: Abstract all the connections to the NSM-SDK-API
        
        Input      : 
                     Operation type, {get, post, delete}                     
                     url, related to the NSM-SDK-API to connect to                     
                     Session header, obtained from the connect operation                     
                     payload, for those operations that require it
                     
        Output     : Response NSM-SDK-API Object + Error Control
        
        Use        : To be used as a public interface
        '''
        import json

        if optype == 'get':
            requeststring = "requests.get(url, headers = header, verify=False)"
        elif optype == 'post':
            requeststring = "requests.post(url, headers = header, verify=False, data=json.dumps(payload))"
        elif optype == 'delete':
            requeststring = "requests.delete(url, headers = header, verify=False)"
            
        try:
            r = eval(requeststring)
            
        except requests.exceptions.ConnectionError:
            # There is a connection Error
            erroroutput = (0,'HTTP Connection Error')
            return erroroutput
            
        except requests.exceptions.Timeout:
            # Inform that the request has timeout
            erroroutput = (0,'HTTP Request Time Out')
            return erroroutput
            
        except requests.exceptions.TooManyRedirects:
            # Inform that the request exceeds the configured number of maximum redirections
            erroroutput = (0,'HTTP Too many redirects')
            return erroroutput
           
        except requests.exceptions.HTTPError:
            # In the event of the rare invalid HTTP response
            erroroutput = (0,'HTTP Bad response')
            return erroroutput
            
        except requests.exceptions.RequestException as e:
            # Unexpected error
            erroroutput = (0,'HTTP Unexpected Error: %s' % e)
            return erroroutput
            
        # The following code raise an alert if the code received is 4XX client error or 5XX server Error
        try:
            r.raise_for_status()
            
        except requests.exceptions.HTTPError: #404 Client Error or 5xx Server error
            erroroutput = (0, 'HTTP output error: %s NSM API output: %s' % (r.status_code, r.text))
            return erroroutput
        return (1,r)
    
    def get_sensors(self):
        ''' 
        
        Description: Get the list of sensors managed by Network Security Manager
        
        Input      : No input
        
        Output     : Tuple with the NSM-SDK-API list of sensors + Error Control
        
        Use        : To be used as a public interface
        '''
        r = self.request_connect('get', 'https://%s/sdkapi/sensors' % self.nsmserver, self.sessionheader)
        
        if r[0] == 1:
               
            self.sensors_raw = self.transform(r[1])
        
            # The following loop get the list of sensors Id manage by the NSM instead of returning
            # the response obtained which has a json structure a prefer to just sent the list of
            # sensors
            self.sensors_id = [[each_sensor['sensorId'] for each_sensor in self.sensors_raw[descriptor]] for descriptor in self.sensors_raw][0]
                       
            return (1,self.sensors_raw)
        else:
            return r
    
    def get_qhosts(self, sensor_id): 
        ''' 
        
        Description: Get the list of quarantine hosts
        
        Input      : Sensor Identification, optional to get the quarantine hosts from.
                     If not specify all sensors will be considered
        
        Output     : Tuple with the list of quarantine hosts + Error Control
        
        Use        : To be used as a public interface
        '''
    
        temp = {}
        
        if sensor_id in self.sensors_id and self.is_supportedsensor(sensor_id) and self.is_sensorup(sensor_id):
                r = self.request_connect('get', 'https://%s/sdkapi/sensor/%d/action/quarantinehost' % (self.nsmserver, sensor_id), self.sessionheader)
                if r[0] == 1:
                    temp.update(self.transform(r[1]))
                    q_hosts=[[(each_qentry['IPAddress'],each_qentry['Duration']) for each_qentry in temp[descriptor]] for descriptor in temp][0]
                    return (1, q_hosts)
                else:
                    return r
        return (0,"Sensor %s down, doesn't exit or model not supported" % sensor_id ) 
                
    def is_supportedsensor(self,sensor_id):
        ''' 
        
        Description: Only M and NS series are supported, this procedure checks if the sensor is supported.
        
        Input      : Sensor identification
        
        Output     : Boolean
        
        Use        : To be used internally in the class
        '''
        
        supportedlist = ['M-8000','M-6050','M-4050','M-2950','M-2850','M-2750','M-1450','M-1250','NS-9100','NS-9200','NS-9300']
        for descriptor in self.sensors_raw:
            for each_entry in self.sensors_raw[descriptor]:
                if each_entry['sensorId'] == sensor_id and each_entry['model'] in supportedlist:
                    return True
        return False
    
    def is_sensorup(self, sensor_Id):
        ''' 
        
        Description: Check if the sensor is active
        
        Input      : Sensor identification
        
        Output     : Boolean
        
        Use        : To be used internally in the class
        '''
        r = self.request_connect('get', 'https://%s/sdkapi/sensor/%s/status' % (self.nsmserver,sensor_Id), self.sessionheader)
        if r[0] == 1:
            if self.transform(r[1])['status']=='ACTIVE':
                return True
            else:
                return False
        else:
            return False
        
    def post_qhost(self, ip_address, sensor_id, duration=15):
        '''
        
        Description: Send a host to quarantine
        
        Input      : 
                     IP Address to be sent to quarantine
                     Sensor identification, optional - to apply the quarantine operation.
                     If not specify all sensors will be considered
                     Duration, optional length of the quarantine operation. Possible values:
                     {15,30,45,60,240,480,720,960,999}
                     If not specify 15 minutes will be considered
                     
        Output     : Error Control
        
        Use        : To be used internally in the class
        '''
       
        temp = {}
        
                
        time = {15:'FIFTEEN_MINUTES',30:'THIRTY_MINUTES',45:'FORTYFIVE_MINUTES',60:'SIXTY_MINUTES',
                240:'FOUR_HOURS',480:'EIGHT_HOURS',720:'TWELVE_HOURS',960:'SIXTEEN_HOURS',
                999:'UNTIL_EXPLICITLY_RELEASED'}
        
        if duration not in time: duration = 15
        
        payload = {
                 'IPAddress': '%s' % ip_address,
                 'Duration': '%s'  % time[duration]
                 }
        
        # Let's check first if the Ip address to quarantine is already in the quarantine area
        quarantine_area = []
        qhosts = self.get_qhosts(sensor_id)
        
        if qhosts[0] == 0: return qhosts
        
        for n in range(len(qhosts[1])):
            quarantine_area.append(qhosts[1][n][0])
                
        if ip_address not in quarantine_area:
        
            if sensor_id in self.sensors_id and self.is_supportedsensor(sensor_id) and self.is_sensorup(sensor_id):
                r = self.request_connect('post', 'https://%s/sdkapi/sensor/%d/action/quarantinehost'
                                             % (self.nsmserver, sensor_id), self.sessionheader, payload)
                if r[0] == 1:
                    temp.update(self.transform(r[1]))
                    response=(1,'IP %s quarantine for %s ' %(ip_address, time[duration]))
                else:
                    return r            
               
            else:
                response=(0,"Sensor %s down, doesn't exit or model not supported" % sensor_id )  
        else:
            response=(0,"IP %s already quarantined" % ip_address)
              
        return response
        
    def delete_qhost(self, ip_address, sensor_id):
        '''
        
        Description: Delete a host from quarantine
        
        Input      : 
                     IP Address to be delete from quarantine
                     Sensor identification, optional - to apply the delete operation.
                     If not specify all sensors will be considered

                     
        Output     : Error Control
        
        Use        : To be used internally in the class
        '''
        temp = {}
        
        # Let's check first if the Ip address to delete is in the quarantine area
        quarantine_area = []
        
        qhosts = self.get_qhosts(sensor_id)
        
        if qhosts[0] == 0: return qhosts
        
        for n in range(len(qhosts[1])):
            quarantine_area.append(qhosts[1][n][0])
        
        if ip_address in quarantine_area:
          
            if sensor_id in self.sensors_id  and self.is_supportedsensor(sensor_id) and self.is_sensorup(sensor_id):
                r = self.request_connect('delete', 'https://%s/sdkapi/sensor/%d/action/quarantinehost/%s' 
                                                % (self.nsmserver, sensor_id, ip_address), self.sessionheader)
                if r[0] == 1:
                    temp.update(self.transform(r[1]))
                    response=(1,"IP %s removed from quarantine" % ip_address)
                else:
                    return r

            else:
                response=(0,"Sensor %s down, doesn't exit or not supported" % sensor_id)
                     
        else:
            response=(0,"IP %s not in quarantined" % ip_address)
            
        return response

def parseargs():
    
    description = 'Basic Operations with Network Security Platform'
    prog        = 'nsmcli'
    usage       = '''nsmcli.py [-h] -u USER -p PASSWORD -nsm NSM_IP
       [-get_sensors][-get_qhosts][-sensor SENSOR_NAME]
       [-i IP_ADDRESS][-quarantine][-remove]
       [-t {15,30,45,60,240,480,720,960,999}][--version]'''
    epilog      = '''Examples:
    1)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -get_sensors
    
    Name          ID        Model     Sensor IP       SW Ver      Sigset Ver  Active
    ********************************************************************************
    M2750-4pocs   1001      M-2750    192.168.0.203   7.5.3.16    7.6.14.9    1     
    
    2)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -get_qhosts

    Quarantined hosts for M2750-4pocs

    IP Address    Time (Milliseconds)
    *********************************
    123.1.1.1     1375816982000      
    124.1.1.1     1375818027000
    
    3)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -quarantine
    
    Sensor  M2750-4pocs IP 10.10.10.100 quarantine for FIFTEEN_MINUTES 

    4)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -remove
    
    Sensor  M2750-4pocs IP 10.10.10.100 removed from quarantine
    
    5)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.101 -quarantine -t 45 -get_sensors -get_qhosts -sensor M2750-4pocs
    
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
    
    6)
    nsmcli.py -u admin -p admin123 -nsm 192.168.0.202 -i 10.10.10.100 -remove -get_sensors -get_qhosts -sensor M2750-4pocs

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
    '''      


    
    parser = argparse.ArgumentParser(epilog=epilog, usage = usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)
    
    # All the elements of the parser group auth_group are required
    auth_group = parser.add_argument_group('Authentication parameters')
    
    arg_help = 'User name to connect to Network Security Manager'
    auth_group.add_argument('-u', required=True, action='store', dest='user', help=arg_help, metavar='  USER')
    arg_help = 'Password to connect to Network Security Manager'
    auth_group.add_argument('-p', required=True, action='store', dest='password', help=arg_help, metavar='  PASSWORD')
    arg_help = 'IP address of Network Security Manager'
    auth_group.add_argument('-nsm', required=True, action='store', dest='nsm_ip', help=arg_help, metavar='NSM IP')
    
    # Rest of elements are optional
    arg_help = 'Get the list of sensors managed by -nsm'
    parser.add_argument('-get_sensors', action='store_true', default=False, dest='get_sensors', help=arg_help)
    
    arg_help = 'Get the list of quarantine hosts.\n'
    arg_help = arg_help + 'Affected by the optional parameter [-sensor]'
    parser.add_argument('-get_qhosts', action='store_true', default=False, dest='get_qhosts', help=arg_help)
    
    arg_help = 'Sensor name to apply the action to.\n'
    arg_help = arg_help + 'if not specify, action will apply in all managed sensors.'
    parser.add_argument('-sensor', action='store', dest='sensor_name', help=arg_help, metavar='SENSOR NAME')
    
    arg_help = 'IP address to be quarantined or removed.\n'
    arg_help = arg_help + 'Affected by the optional parameter [-sensor]'
    parser.add_argument('-i', action='store', dest='q_ip', help=arg_help, metavar='     IP ADDRESS')
    
    arg_help = 'Quarantine period. 15 minutes by default.\n'
    arg_help = arg_help + 'Possible values:\n'
    arg_help = arg_help + '  - 15  --> FIFTEEN MINUTES\n'
    arg_help = arg_help + '  - 30  --> THIRTY MINUTES\n'
    arg_help = arg_help + '  - 45  --> FORTYFIVE MINUTES\n'
    arg_help = arg_help + '  - 60  --> SIXTY MINUTES\n'
    arg_help = arg_help + '  - 240 --> FOUR HOURS\n'
    arg_help = arg_help + '  - 480 --> EIGHT HOURS\n'
    arg_help = arg_help + '  - 720 --> TWELVE_HOURS\n'
    arg_help = arg_help + '  - 960 --> SIXTEEN_HOURS\n'
    arg_help = arg_help + '  - 999 --> UNTIL_EXPLICITLY_RELEASED'
    parser.add_argument('-t', choices=[15,30,45,60,240,480,720,960,999], type=int, default='15', action='store', dest='duration', help=arg_help)
    
    arg_help = 'Send the host specified in [-i] to quarantine.\n'
    arg_help = arg_help + 'Affected by the optional parameter [-sensor]'
    parser.add_argument('-quarantine', action='store_true', default=False, dest='quarantine', help=arg_help)
    
    arg_help = 'Remove the host specified in [-i] from quarantine.\n'
    arg_help = arg_help + 'Affected by the optional parameter [-sensor]'
    parser.add_argument('-remove', action='store_true', default=False, dest='remove', help=arg_help)
    
    parser.add_argument('--version',action='version',version='Carlos Munoz (carlos_munoz@mcafee.com)\n%(prog)s 1.0 (08/06/2013)')
    
    return parser.parse_args()

def get_sensorlist(myNSM):
    error_control, data = myNSM.get_sensors()
    
    if error_control == 0:
        print 'Error - getting sensor list: ', data
        #print 'Information returned: \n', data
        #sys.exit(0)
    else:
        sensor_list = {}
        for descriptor in data:
            for sensor in data[descriptor]:
                
                name                = '*'*8
                model               = '*'*8
                sensorIPAddress     = '*'*8
                sensorId            = '*'*8
                softwareVersion     = '*'*8
                sigsetVersion       = '*'*8
            
                if 'name'            in sensor:    name              = sensor['name']
                if 'model'           in sensor:    model             = sensor['model']
                if 'sensorIPAddress' in sensor:    sensorIPAddress   = sensor['sensorIPAddress']
                if 'sensorId'        in sensor:    sensorId          = sensor['sensorId']
                if 'SoftwareVersion' in sensor:    softwareVersion   = sensor['SoftwareVersion']
                if 'SigsetVersion'   in sensor:    sigsetVersion     = sensor['SigsetVersion']
                
                sensor_list[name]=[sensorId, model, sensorIPAddress, softwareVersion, sigsetVersion, myNSM.is_sensorup(sensorId)]
                
    return sensor_list

def get_qhosts(myNSM, sensor_name):
    
    response = {}
    # First check if sensor_name has a value   
    if sensor_name:
        sensors = get_sensorlist(myNSM)
        if sensor_name in sensors:
            sensor_Id = sensors[sensor_name][0]
            error_control, data = myNSM.get_qhosts(sensor_Id)
            
            if error_control == 0:
                print 'Error - getting quarantine hosts: ', data
                #print 'Information returned: \n', data
                #myNSM.disconnect()
                #sys.exit(0)
            else:
                response[sensor_name] = data                
        else:
            # sensor name doesn't exit
            print 'Error - getting quarantine hosts: Sensor %s not managed by Network Security Manager' % sensor_name
            #myNSM.disconnect()
            #sys.exit(0)
                
    else:
        # All quarantine host from all sensor must be obtained
        sensor_list = get_sensorlist(myNSM)
        for sensor_name in sensor_list:
            sensor_Id = sensor_list[sensor_name][0]
            error_control, data = myNSM.get_qhosts(sensor_Id)
            if error_control == 0:
                print 'Error - getting quarantine hosts: ', data                
            else:
                response[sensor_name] = data
                
    return response       

def quarantine_ip(myNSM, sensor_name, ip, time):
    
    response = {}

    # First check if sensor_name has a value   
    if sensor_name:
        sensors = get_sensorlist(myNSM)
        if sensor_name in sensors:
            sensor_Id = sensors[sensor_name][0]
            error_control, data = myNSM.post_qhost(ip, sensor_Id, time)
            
            if error_control == 0:
                print 'Error - quarantine: ', data
                #print 'Information returned: ', data
                #print 'Disconnecting from Network Security Manager'
                #myNSM.disconnect()
                #sys.exit(0)
            else:
                response[sensor_name] = data                
        else:
            # sensor name doesn't exit
            print 'Error - quarantine: Sensor %s not managed by Network Security Manager' % sensor_name
            #print 'Disconnecting from Network Security Manager'
            #myNSM.disconnect()
            #sys.exit(0)
                
    else:
        # sensor name not indicated send the ip address to the quarantine of all sensors
        sensor_list = get_sensorlist(myNSM)
        for sensor_name in sensor_list:
            sensor_Id = sensor_list[sensor_name][0]
            error_control, data = myNSM.post_qhost(ip, sensor_Id, time)
            if error_control == 0:
                print 'Error - quarantine: ', data
         
            else:
                response[sensor_name] = data
                
    return response              

def remove_ip(myNSM, sensor_name, ip):
    response = {}
  
    # First check if sensor_name has a value   
    if sensor_name:
        sensors = get_sensorlist(myNSM)
        if sensor_name in sensors:
            sensor_Id = sensors[sensor_name][0]
            error_control, data = myNSM.delete_qhost(ip, sensor_Id)
            
            if error_control == 0:
                print 'Error - remove: ', data
                #print 'Disconnecting from Network Security Manager'
                #myNSM.disconnect()
                #sys.exit(0)
            else:
                response[sensor_name] = data                
        else:
            # sensor name doesn't exit
            print 'Error - remove: Sensor %s not managed by Network Security Manager' % sensor_name
            #print 'Disconnecting from Network Security Manager'
            #myNSM.disconnect()
            #sys.exit(0)
                
    else:
        # sensor name not indicated send the ip address to the quarantine of all sensors
        sensor_list = get_sensorlist(myNSM)
        for sensor_name in sensor_list:
            sensor_Id = sensor_list[sensor_name][0]
            error_control, data = myNSM.delete_qhost(ip, sensor_Id)
            if error_control == 0:
                print 'Error - remove : ', data
         
            else:
                response[sensor_name] = data
                
    return response

def main(): 
    # Get the list of parameters passed from command line
    options = parseargs()
    
    # Create the NSM object and connect to it
    myNSM = nsm(options.nsm_ip)
    error_control, data = myNSM.connect(options.user, options.password)
    
    if error_control == 0:
        print 'Error - connect: ', data
        sys.exit(0)
    # ***************************************
    
    # if the switch quarantine has been set the IP address passed to the system must be put in quarantine
    if options.quarantine:
        if options.q_ip:
            result = quarantine_ip(myNSM, options.sensor_name, options.q_ip, options.duration)
            for sensor in result:
                print '\nSensor ', sensor, result[sensor]
        else:
            print 'Error - quarantine: set the IP address to be sent to quarantine with the switch -i'

    # **************************************************
    
    # if the switch remove has been set, the IP address passed to the system must be removed from quarantine
    if options.remove:
        if options.q_ip:
            result = remove_ip(myNSM, options.sensor_name, options.q_ip)
            for sensor in result:
                print '\nSensor ', sensor, result[sensor]
        else:
            print 'Error - remove: set the IP address to be removed from quarantine with switch -i'
    # *************************************************
    
    # if the switch get-sensors has been set get the list    
    if options.get_sensors:
        sensor_list = get_sensorlist(myNSM)
        # Printing the header for the list of sensors
        print '\n{:<14}{:<10}{:<10}{:<16}{:<12}{:<12}{:<6}'.format('Name', 'ID', 'Model', 'Sensor IP', 'SW Ver', 'Sigset Ver', 'Active')
        print '*'*80
        for sensor_name in sensor_list:
            
            sensorId        = sensor_list[sensor_name][0]
            model           = sensor_list[sensor_name][1]
            sensorIPAddress = sensor_list[sensor_name][2]
            softwareVersion = sensor_list[sensor_name][3]
            sigsetVersion   = sensor_list[sensor_name][4]
            active          = sensor_list[sensor_name][5]
            
            print '{:<14}{:<10}{:<10}{:<16}{:<12}{:<12}{:<6}'.format(sensor_name, sensorId, model, sensorIPAddress, softwareVersion, sigsetVersion, active)
            
    # **************************************************
    
    
    # if the switch get_qhosts has been set get the list
    if options.get_qhosts:
        q_hosts = get_qhosts(myNSM, options.sensor_name)

        if q_hosts:
            # the dictionary contents data
            for sensor in q_hosts:
                print '\nQuarantined hosts for %s\n'% sensor
                print '{:<16}{:<19}'.format('IP Address','Time (Milliseconds)')
                print '*'*33
                for n in range(len(q_hosts[sensor])):
                    print '{:<16}{:<19}'.format(q_hosts[sensor][n][0],q_hosts[sensor][n][1])
        #else:
            # the dictionary is empty
        #   print 'Non quarantine hosts'
    # **************************************************
  
    
    error_control, data =  myNSM.disconnect()
    
    if error_control == 0:
        print 'Error - disconnect: ', data
        sys.exit(0)

if __name__ == '__main__':
    main()
    
