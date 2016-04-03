package com.vscanweb.vscan;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Servlet implementation class VscanServlet
 */
@WebServlet("/VscanServlet")
public class VscanServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public VscanServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		 OutputStream out = response.getOutputStream();
		 String targetUrl = request.getParameter("targetUrl");
		 writeForm(out, "", "", "", "");		
		 
	} // End do get

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		OutputStream out = response.getOutputStream();
		String targetUrl = request.getParameter("targetUrl");
		String protocol = request.getParameter("protocol");
		String urlError = request.getParameter("urlError");
		//String protocol = "";
		String protocolError = "";
		RequestDispatcher dispatcher = request.getRequestDispatcher("/ScanResult");
		//UrlValidator urlValidator = new UrlValidator();

		if(!targetUrl.contains("https://")){
			targetUrl = "https://"+ targetUrl;
		}


		if (targetUrl.length() > 12){
			//DefaultPortScan.scan(targetUrl);
			if(DefaultPortScan.tlsPortisOpen(targetUrl))
			dispatcher.forward(request, response);
			else {
				urlError = "Destination URL not listening on port 443 or not reachable from here";
				writeForm(out, targetUrl, urlError, protocol, protocolError);
			}
		} else {
			urlError = "please provide a Valid https URL";
			writeForm(out, targetUrl, urlError, protocol, protocolError);

		} 

	} //end doPost 
	
	
	  public static void writeForm(OutputStream out, String targetUrl, String urlError, String protocol, String protocolError) throws IOException {
	    	
	    	//out.write("<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>".getBytes());
	    	//out.write("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">".getBytes());
	    	out.write("<!DOCTYPE html >".getBytes());
	    	out.write("<html lang = \"en\" >".getBytes());
	    	//out.write("<html xmlns=\"http://www.w3.org/1999/xhtml\">".getBytes());
	    	out.write("<head>".getBytes());
	    	out.write("<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">".getBytes());
	    	//out.write("<link rel='stylesheet' type='text/css' href='\" + request.getContextPath() +  \"vscanstyle.css' />".getBytes());
	    	
	    	out.write("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-1\" />".getBytes());
	    	out.write("<title>SSL/TLS Ciphers Test</title>".getBytes());
	    	//out.write("<script src = \"SelectedProtocol.js\"></script>".getBytes());
	    	out.write("<script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.4.5/angular.min.js\"></script>".getBytes());
	    	//out.write("<script src = \"SelectedProtocol.js\"></script>".getBytes());
	    	out.write("</head>".getBytes());
	    	out.write("<body>".getBytes());
	    	out.write("<div class=\"container\">".getBytes());
	    	out.write("<h1> Welcome to EasyTLS version 0.5 </h1>".getBytes());
	    	out.write("<h3>EasyTLS is a user friendly SSL/TLS testing software. Lots of cool new features will be added soooon.</h3>".getBytes());
	    	out.write("<form method = \"post\" action =\"/Vscan/VscanServlet\">".getBytes());
	    	out.write("<div class=\"form-group\">".getBytes());
	    	out.write("<div class=\"col-xs-5\">".getBytes());
	    	out.write(("Enter a URL to Scan: <input type = \"text\" name= \"targetUrl\" class=\"form-control\" value = \""+targetUrl+ "\"/>" +"<font size=\"3\" color=\"red\">"  + urlError +   "</font><br/>").getBytes());
	    	out.write(("</div>").getBytes());
	    	out.write(("</div>").getBytes());
	    	
	    	out.write("<div class=\"form-group\">".getBytes());
	    	out.write("<div class=\"col-xs-2\">".getBytes());
	    	out.write(("Select protocol: ").getBytes());
	    	// Begin select
	    	
	    	out.write(("<select id = \"protocolid\" class=\"form-control\" value = \" "+protocol+ "  \" name= \"protocol\">").getBytes());
	    	out.write(("<option value=\"SSLv3\">SSLv3</option>").getBytes());
	    	out.write(("<option selected=\"selected\" value=\"TLSv1\">TLSv1.0</option>").getBytes());
	    	out.write(("<option value=\"TLSv1.1\">TLSv1.1</option>").getBytes());
	    	out.write(("<option value=\"TLSv1.2\">TLSv1.2</option>").getBytes());
	    	out.write(("</select>").getBytes());
	    	out.write(("</div>").getBytes());
	    	out.write(("</div>").getBytes());
	    	
	    	//out.write(("<br><br>").getBytes());
	    	// To maintain the selected value: 
	    	//http://stackoverflow.com/questions/11309662/how-to-keep-dropdownlist-value-same-after-refresh-the-page
	    	
	    	//End select
	    	out.write("<div class=\"form-group\">".getBytes());
	    	out.write("<div class=\"col-sm-10\">".getBytes());
	    	//out.write("<div class=\"col-xs-2\">".getBytes());
	    	out.write("<input type = \"submit\" class=\"btn btn-default\" value = \"Scan this URL\" />".getBytes());
	    	out.write(("</div>").getBytes());
	    	out.write(("</div>").getBytes());
	    	out.write("</form>".getBytes());
	    	out.write(("</div>").getBytes());
	    	//String ljs= "onload = document.getElementById('protocolid').value=" + "\""+ protocol  +"\""+ " ;";
	    	 //out.write(ljs.getBytes());
	    	if(protocol.length() != 0) {
	    	 String ljs= "<script> document.onload = document.getElementById('protocolid').value=" + "\""+ protocol  +"\""+ " </script>";
	    	 out.write(ljs.getBytes());
	    	}
	    	out.write("</body>".getBytes());
	    	out.write("</html>".getBytes());	    	
	    }

}
