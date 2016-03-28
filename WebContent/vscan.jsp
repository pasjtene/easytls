<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    <%@ page import = "com.vscanweb.vscan.Vscan" %>
 
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Https Ciphers strength testing</title>
</head>
<body>

<form method = "post" action ="/Vscan/vscan.jsp">
enter The URL to scan: <input type = "text" name= "targetUrl" value = "<%= request.getParameter("targetUrl") %>" /> <div class = "error"> <%= session.getAttribute("urlError") %></div> <br/>
<input type = "submit" value = "Scan this URL" />
</form>

 
  <% if (request.getParameter("targetUrl") != null) { %>
  <h1> The target URL is: <%= request.getParameter("targetUrl") %> </h1> 
  <% Vscan.VscanMain(request, response); %>
  Testing with: 
  <div class = "error"> <%=   session.getAttribute("protocol") %> <br/>	
      List of cipher suies supported by the target: <br/>
     <div class = "error"> <%=   session.getAttribute("listOfSuccessfulCiphers") %>	
    <%	//return;
    }%>
</body>
</html>