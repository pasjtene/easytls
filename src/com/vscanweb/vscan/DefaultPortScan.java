package com.vscanweb.vscan;

import java.net.InetSocketAddress;
import java.net.Socket;

public class DefaultPortScan {
	
	public static void scan(String targetUrl) {
	     int[] knownPorts = {22, 23, 53, 80, 161, 443, 4353};
	     
	      String ip = getTargetIP.getIpFromHost(targetUrl);
	      System.out.println("Scanning default port  using target IP address: " +ip);
		
		for(int i = 0; i < knownPorts.length; ++i) {
			if (portIsOpen(ip, knownPorts[i], 200))
	            System.out.println("port " +knownPorts[i] + " is open");
	        else
	            System.out.println("port " +knownPorts[i] + " is closed");
	}
	}
	
	public static boolean tlsPortisOpen(String targetUrl) {
	      String ip = getTargetIP.getIpFromHost(targetUrl);
	      System.out.println("Scanning default port  using target IP address: " +ip);
		
		if (portIsOpen(ip, 443, 300)) {
	            System.out.println("port 443 is open");
	            return true;
		}
	        else {
	            System.out.println("port 443 is closed");
	            return false;
	        }
	
	}
	
	/*
	public static boolean tlsPortIsopen(String ip, int port, int timeout) {
		try {
			Socket socket = new Socket();
			socket.connect(new InetSocketAddress(ip, port), timeout);
			socket.close();
			return true;
		} catch (Exception ex) {
			return false;
		}
	}
*/	

	static boolean portIsOpen(String ip, int port, int timeout) {
	        try {
	            Socket socket = new Socket();
	            socket.connect(new InetSocketAddress(ip, port), timeout);
	            socket.close();
	            return true;
	        } catch (Exception ex) {
	            return false;
	        }
	    }


}
