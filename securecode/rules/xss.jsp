<!-- ruleid: kisa-xss-jsp-unescaped -->
<p><%= request.getParameter("q") %></p>
<!-- ruleid: kisa-xss-jsp-unescaped -->
<c:out value="${q}" escapeXml="false"/>
<!-- ok: kisa-xss-jsp-unescaped -->
<c:out value="${q}"/>
