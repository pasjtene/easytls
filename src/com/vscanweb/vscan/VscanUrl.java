package com.vscanweb.vscan;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class VscanUrl {
	 public static void VscanUrlMain(HttpServletRequest request, HttpServletResponse response) throws Exception {
		 HttpSession session = request.getSession(true);
		 String targetUrl = "";
	       session.setAttribute("targetUrl", targetUrl);
	       //System.out.println("Target: " + targetUrl );
	       	response.sendRedirect("/Vscan/targetUrlProcessing.jsp");
	       	
	 }

}
