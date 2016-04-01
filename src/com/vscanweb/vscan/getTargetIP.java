package com.vscanweb.vscan;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class getTargetIP {
	
	public static String getIpFromHost(String targetHost) {
        //String targetHost = "https://www.google.com";
        String ipaddress  = " ";
        targetHost  = RemoveUrlPrefix.trim(targetHost);
        
        try {
            InetAddress address = InetAddress.getByName(targetHost);
            System.out.println("The Ip address is: "+address.getHostAddress());
            ipaddress = address.getHostAddress();
            
            
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ipaddress;
    }
    

}
