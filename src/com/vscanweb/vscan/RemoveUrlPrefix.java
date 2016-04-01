package com.vscanweb.vscan;

import java.net.URL;

public class RemoveUrlPrefix {
	
	public static String trim(String receivedUrl) {
	    String trimResult = " ";
	    {
	        try {
	            URL url = new URL(receivedUrl);
	            String protocol = url.getProtocol();
	            String result = receivedUrl.replaceFirst(protocol + ":", "");
	            if (result.startsWith("//"))
	            {
	                result = result.substring(2);
	            }

	            System.out.println(result);
	             trimResult  = result;
	        } catch (Exception e) {
	            System.out.println(e);
	        }
	        return trimResult;
	    }
	}
}
