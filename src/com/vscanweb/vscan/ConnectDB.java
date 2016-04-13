package com.vscanweb.vscan;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

public class ConnectDB {
	 int numberOfVulnerabilities = 0;
	    
     Connection connection;
	public ConnectDB() throws Exception	{
	try {
	Class.forName("com.mysql.jdbc.Driver").newInstance();
	System.out.println("Database driver loaded");
	} catch (ClassNotFoundException e) {
	System.out.println("Error: Cannot load the driver");
	}
	}

	public void connectToDB() throws Exception {
		//OutputStream out = new OutputStream();
		try {
			connection = DriverManager.getConnection ("jdbc:mysql://localhost/vscan", "root", "jt.pas");
			System.out.println("Connected to the database.");
			//out.write("Connected to the database".getBytes());
			} catch (Exception e) {
				System.out.println("Cannot connect to the database.");
			}
		}
        
        public void execSQL(OutputStream out, ArrayList<String> recivedlisOfCodes) throws IOException {
            ArrayList<String> listOfCodes = new ArrayList<String>();
           
            listOfCodes = recivedlisOfCodes;
            
            out.write("<BR /> <BR /> <h4>List of vulnerabilities corresponding to the cipher suites used.</h4> ".getBytes());
            
            for (String code: listOfCodes){
               try {
                Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery("Select * from vulnerabilities");
                
                while (rs.next()) {
                	String rsWeb = " ";
                    if(rs.getString(2).equalsIgnoreCase(code)){
                    numberOfVulnerabilities+=1;
                    
                    System.out.println("\n");
                  
                    // uncomment following two lines to see vulnerability codes
                   // rsWeb = "<BR />" + rs.getString(1)+ ":  " + rs.getString(2)+ " " + rs.getString(3)+ " " + rs.getString(4)+ "<BR /> Category: " + rs.getString(5)+ " <BR> CVSS Base Score: " + rs.getString(6)+ " <BR /> Severity: " + rs.getString(7)
                    //+ " <BR /> Ask F5 Solution: " + rs.getString(11)+ " <BR /> Solution link: <a href=\"" + rs.getString(10) + " \" " +" target= \"_blank\">" + rs.getString(11) +" </a><BR />Last updated: " + rs.getString(9) + "<BR />";
                    
                
                    rsWeb =  "<BR /> Vulnerability ID:  " + rs.getString(3)+ "<BR /> Description:  " + rs.getString(4)+ "<BR /> Category: " + rs.getString(5)+ " <BR> CVSS Base Score: " + rs.getString(6)+ " <BR /> Severity: " + rs.getString(7) +
                             " <BR /> Ask F5 Solution : <a href=\"" + rs.getString(10) + " \" " +" target= \"_blank\">" + rs.getString(11) +" </a><BR />Last updated: " + rs.getString(9) + "<BR />";
                    
                    out.write(rsWeb.getBytes());
                    out.flush();
                    
                    
                    
                    System.out.println(rs.getString(1)+ ":  " + rs.getString(2)+ " " + rs.getString(3)+ " " + rs.getString(4)+ "<BR /> Category: " + rs.getString(5)+ " <BR /> CVSS Base Score: " + rs.getString(6)+ " <BR> Severity: " + rs.getString(7)
                           + " <BR /> Ask F5 Solution: " + rs.getString(11)+ " \n Solution link: " + rs.getString(10) + " <BR /> Last updated: " + rs.getString(9));
                
                 
                    }
                }
            } catch (Exception e) {
                System.out.println("Error executing SQL");
            }
            System.out.println();
            }
             System.out.println("Number of vulnerabilities found "+numberOfVulnerabilities);
             
             // adding spaces at the end of the page.
             out.write("<BR />".getBytes());
             out.write("<BR />".getBytes());
             //Closing the global page div
             out.write("</div>".getBytes());
 			 out.flush();
        }


}
