package com.vscanweb.vscan;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;

public class CheckWeackCiphers {
	 public static void parseTargetCipher(OutputStream out, ArrayList<String> supportedCipherList, String testedProtocol) throws IOException {
	        //We only run this test if the received supported cipher list is NOT empty.
	        if (!supportedCipherList.isEmpty()){
	        ArrayList<String> vulnerabilityCodeList = new ArrayList<String>();
	        ArrayList<String> cveList = new ArrayList<String>();
	        HashMap<String, String>listOfCiphersAndGrade = new HashMap<String, String>();
	        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "A");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "A");
	        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_CBC_SHA256", "A");
	        listOfCiphersAndGrade.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "A");
	        listOfCiphersAndGrade.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "A");
	        listOfCiphersAndGrade.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "A-");
	        listOfCiphersAndGrade.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "A-");
	        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_SHA", "E");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "C");
	        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "A+");
	        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_GCM_SHA256", "A+");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "A+");
	        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_MD5", "F");
	        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_SHA", "E");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "E");
	        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "E");
	        listOfCiphersAndGrade.put("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "C");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "D");
	        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "D");
	        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_CBC_SHA", "C");
	        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "C");
	        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "C");
	        Boolean cbctested = false;
	        Boolean rc4tested = false;
	        
	        for (String cipherSuite: listOfCiphersAndGrade.keySet()){
	            if (supportedCipherList.contains(cipherSuite)){
	            System.out.println(cipherSuite + " Grade " + listOfCiphersAndGrade.get(cipherSuite));
	            //out.write("In parseTarget".getBytes());
	        }
	        }
	        
	        for (String cipherSuite: supportedCipherList){
	                      
	            if (cipherSuite.toLowerCase().contains("cbc") && (cbctested == false)){
	            cbctested = true;
	            vulnerabilityCodeList.add("cbc");
	            
	            }else{
	                   if (cipherSuite.toLowerCase().contains("rc4") && (rc4tested == false)){  
	                        rc4tested = true;
	                        vulnerabilityCodeList.add("rc4");
	                }            
	            }
	            
	            if (cipherSuite.toLowerCase().contains("cbc") && ((testedProtocol.equalsIgnoreCase("TLSv1")) || (testedProtocol.equalsIgnoreCase("SSLv3")))  ){
	                    if(!vulnerabilityCodeList.contains("cbc-tlsv1"))
	                    vulnerabilityCodeList.add("cbc-tlsv1");
	                    
	                }
	            
	            if (cipherSuite.toLowerCase().contains("cbc") && ((testedProtocol.equalsIgnoreCase("TLSv1.1")) || (testedProtocol.equalsIgnoreCase("TLSv1.2")))  ){
                    if(!vulnerabilityCodeList.contains("cbctls112"))
                    vulnerabilityCodeList.add("cbctls112");
                    
                }
	            
	            if (cipherSuite.toLowerCase().contains("cbc") && ((testedProtocol.equalsIgnoreCase("TLSv1.1")) || (testedProtocol.equalsIgnoreCase("TLSv1.2")) || (testedProtocol.equalsIgnoreCase("TLSv1")) )  ){
                    if(!vulnerabilityCodeList.contains("cbctls1x"))
                    vulnerabilityCodeList.add("cbctls1x");
                    
                }
	            
	            if (testedProtocol.equalsIgnoreCase("SSLv3") && (!vulnerabilityCodeList.contains("sslv3")))
	                vulnerabilityCodeList.add("sslv3");
	            
	               }
	        
	        System.out.println("List of codes: "+ vulnerabilityCodeList);
	       try {
	       ConnectDB conn = new ConnectDB();
	       conn.connectToDB();
	       //Call execSQL with the list of codes that will be checked before display
	       conn.execSQL(out, vulnerabilityCodeList);
	       } catch (Exception e) {
		     System.out.println("Cannot connect to the database.");
	       }     
	    }else {
	    System.out.println("Protocol "+ testedProtocol+ " is not supported.");
	}
	    }

}
