package com.vscanweb.vscan;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Servlet implementation class ScanResult
 */
@WebServlet("/ScanResult")
public class ScanResult extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ScanResult() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
	
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		OutputStream out = response.getOutputStream();
    	String targetUrl = request.getParameter("targetUrl");
    	String urlError = request.getParameter("urlError");
    	String protocol = request.getParameter("protocol");
    	String protocolError = "";
    	
    	if(!targetUrl.contains("https://")){
    		targetUrl = "https://"+ targetUrl;
    	}
    	
    	VscanServlet.writeForm(out, targetUrl, "", protocol, "");
    	
        System.out.println("Target: " + targetUrl );
     HttpSession session = request.getSession(true);
        session.setAttribute("targetUrl", targetUrl);
        out.write("<div class=\"container\">".getBytes());
       String s1 = "<html><head><title>SSL/TLS Ciphers test</title>" + "</head><body>The target URL is: " + targetUrl+"</body></html>";
       out.write(s1.getBytes());
      // DefaultPortScan.scan(targetUrl);
       // out.write(result.getBytes());
       
    	// Begin C1 - The goal of this is to allow connection to some sites with invalid cert.
        //This is important when we want to test self signed certificates in Lab environment
    	//HttpSession session = request.getSession(true);
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
        public void checkServerTrusted(X509Certificate[] certs, String authType) {  } 
            }
        };
               
        // create trusted Host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
      HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);  
      //CheckCliArgs.parseArgs(args);
       //String targetUrl = args[0];
      // String targetUrl = "";
      // session.setAttribute("targetUrl", targetUrl);
       
       //String targetUrl = request.getParameter("targetUrl");
       //System.out.println("Target: " + targetUrl );
            // We loop through different versions of SSL / TLS: TLSv1.2, TLSv1.1, TLSv1, SSLv3
     // Some details in https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https
      ArrayList<String>sslTlsVersions  = new ArrayList<String>();
      //sslTlsVersions.add("SSLv3"); 
      //sslTlsVersions.add("TLSv1");
      //sslTlsVersions.add("TLSv1.1"); 
      //sslTlsVersions.add("TLSv1.2");
      
      sslTlsVersions.add(protocol);
      out.write("<table class=\"table table-hover\">".getBytes());
      out.write("<thead>".getBytes());
      out.write("<tr>".getBytes());
      out.write("<th>No.</th>".getBytes());
      out.write("<th>Cipher Suite</th>".getBytes());
      out.write("</tr>".getBytes());
      out.write("</thead>".getBytes());
      out.write("</tbody>".getBytes());
     
      out.flush();
        //String protocol = "SSLv3";
        for (String Protocol: sslTlsVersions) {
            System.out.println();
            session.setAttribute("protocol", Protocol);
            System.out.println("Testing with protocol "+ Protocol);
            String out1 = " <br /> Connecting with: "+ Protocol;
            out.write(out1.getBytes());
            out.flush();
            System.out.println();
            java.lang.System.setProperty("https.protocols", Protocol);
            try {
            SSLContext sc = SSLContext.getInstance(Protocol);
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());   
            } catch (Exception e) {
            	e.printStackTrace();
            }
  

        // The list of cipher suites that will be used by th eclient to connect to the target repetitively
        // is defined below in an Array list. 
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        String supportedCiphers[] = sf.getSupportedCipherSuites();
            
       //To get all ciphers, including those that java has disabled by default
       // we need to comment out the line jdk.tls.disabledAlgorithms=MD5, SSLv3, DSA, RSA keySize < 2048
       // in [JAVA_HOME]/jre/lib/security/java.security. For example C:/program file/java/jdk1.8.0//jre/lib/security/java.security
        
       
                       
                ArrayList<String>listOfSuccessfulCiphers  = new ArrayList<String>();
                System.out.println("Testing CipherSuites accepted by tartget please wait...");
                String out2 = " <br /> Testing CipherSuites accepted by tartget please wait...<br />";
                out.write(out2.getBytes());
                out.flush();
                int numberOfCiphers = 0;
                     for (int j = 0; j < supportedCiphers.length; j++) {
                         System.out.print(" " + (j+1));
                         System.out.print(" Connecting with " + supportedCiphers[j]);
                         //set the current cipher suite as the one for next connection
                         System.setProperty("https.cipherSuites", supportedCiphers[j]);
                         String successfulCipher = "";
                         try {
                         successfulCipher = new Vscan().connectToUrlForCVE(targetUrl);
                         } catch (Exception e) {
                        	 System.out.println("Something is wrong");
                         }
                     // Add the successful cipher to the list if the connection did not fail
                        if (successfulCipher.length() != 0){
                            listOfSuccessfulCiphers.add(successfulCipher);
                            numberOfCiphers += 1;
                            
                             String out3 = numberOfCiphers +": ";
                             out.write("<tr>".getBytes());
                             out.write("<td>".getBytes());
                              out.write(out3.getBytes());
                        out.write("</td>".getBytes());
                        out.flush();
                        
                        String out4 = successfulCipher;
                        
                        
                        out.write("<td>".getBytes());
                        out.write(out4.getBytes());
                  out.write("</td>".getBytes());
                  out.write("</tr>".getBytes());
                  
                            
                       
                        out.flush();
                        
                        }
                        
                    } 
                     out.write("</tbody>".getBytes());    
                     
                     out.write("</table>".getBytes());
                     out.flush();
                     out2 = "<br/> Number of Cipher suites supported by " + targetUrl+ "  with: " + Protocol + ": " + numberOfCiphers + "<br/>";
                     out.write(out2.getBytes());
                     
                   System.out.println("\n");
                   System.out.println("List of cipher suites supported by the target:");
                   System.out.println(listOfSuccessfulCiphers);
                   System.out.println("\n");
                   System.out.println("Number of cipher suites supported by the target:"+ listOfSuccessfulCiphers.size());
                   System.out.println("List of vulnerabilities and solution containing work around:");
                   session.setAttribute("listOfSuccessfulCiphers", listOfSuccessfulCiphers);
                   
                   //out.println("<html><head><title>List of Ciphers used by Target: </title>" + "</head><body><h1 style=\"color:blue;\">List of Ciphers used by Target: </style></h1>" + listOfSuccessfulCiphers +"</body></html>");
                   String l1 = " <br /> List of Ciphers supported by the target: "+ listOfSuccessfulCiphers;
                   out.write(l1.getBytes());
                   out.write("</div>".getBytes());
                   // send the ArrayList containing the list of Successful Ciphers to the CheckWeakCiphers class for evaluation. a
                  CheckWeackCiphers.parseTargetCipher(listOfSuccessfulCiphers, protocol);
                   // test CBC Vulnerabilities; only check one cipher suite with "CBC"
                   Boolean cbctest = false;
                   for (int k=0; k < listOfSuccessfulCiphers.size(); k++){
                       String cCS = listOfSuccessfulCiphers.get(k);
                        if (cCS.toLowerCase().contains("cbc")){
                           if (cbctest == false){
                            
                           cbctest = true;
                           
                       // CheckWeackCiphers.parseTargetCipher(listOfSuccessfulCiphers.get(k));
                           }
                       }
                       }
                   
                   //fololowing print the headers and the contain using a predefined cipher which is expected to work
                    System.setProperty("https.cipherSuites", "TLS_RSA_WITH_AES_128_CBC_SHA");
                     //new Vscan().connectToUrl(targetUrl);
                
    }
        //Following print the content and the cert details.
       
        ConnectToUrlForContent.connectToUrl(targetUrl);
        //we could also use the methods defined in this file.
        //new Vscan().connectToUrl(targetUrl);
       // if (targetUrl != null) {
       // HttpSession session = request.getSession(true);
        //session.setAttribute("targetUrl", targetUrl);
	       //System.out.println("Target: " + targetUrl );
	      // response.sendRedirect("/Vscan/targetUrlProcessing.jsp");
       // }	
		
}
	
}
