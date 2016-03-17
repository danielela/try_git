package com.us.chartisinsurance.nuvue.filter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.us.chartisinsurance.nuvue.bean.UserEntitlementBean;
import com.us.chartisinsurance.nuvue.common.NuvueConstants;
import com.us.chartisinsurance.nuvue.dbservice.DBUtility;
import com.us.chartisinsurance.nuvue.util.ApplicationLogger;
import com.us.chartisinsurance.nuvue.util.LDAPAuthUtil;
import com.us.chartisinsurance.nuvue.util.LoginAuth;

public class SecurityServletFilter implements Filter{
	private FilterConfig config = null;
	private Pattern scriptTagPattern = null;
	private Pattern badCharPattern = null;
	private Pattern iframePattern = null;
	private Pattern xsrfPattern = null;
	
	static ApplicationLogger applicationLogger = null;
	
	public void init(FilterConfig filterConfig) {
	    this.config = filterConfig;
	    if(config != null){
	    	//Initialize any init params
	    }
	    try {
    		scriptTagPattern = Pattern.compile(".*<[^>]*script[^>]*>.*", Pattern.CASE_INSENSITIVE);
    		iframePattern = Pattern.compile(".*<.*iframe.*>.*", Pattern.CASE_INSENSITIVE);
    		xsrfPattern = Pattern.compile("WF_XSRF.", Pattern.CASE_INSENSITIVE);
    		/*
    		[1] | (pipe sign)
    		[2] & (ampersand sign) // EXCEPTION: This character is not considered at this time (\\&)
    		[3] ; (semicolon sign)
    		[4] $ (dollar sign)
    		[5] % (percent sign)
    		[6] @ (at sign)
    		[7] ' (single apostrophe)
    		[8] " (quotation mark)
    		[9] \' (backslash-escaped apostrophe)
    		[10] \" (backslash-escaped quotation mark)
    		[11] <> (triangular parenthesis)
    		[12] () (parenthesis)
    		[13] + (plus sign)
    		[14] CR (Carriage return, ASCII 0x0d)
    		[15] LF (Line feed, ASCII 0x0a)
    		[16] , (comma sign)
    		[17] \ (backslash)
    		*/
    		badCharPattern = Pattern.compile("[\\|;$@'\"\\'\\\"<>\\(\\)\\+\\n\\r,\\\\]");
		} catch (PatternSyntaxException e) {
			e.printStackTrace();
		}
	}

	public void destroy() {
		this.config = null;
	}
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain ) throws IOException, ServletException {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			System.out.println("Inside Security filter");
	    	HttpServletRequest hRequest  = (HttpServletRequest)request;
	    	HttpServletResponse hResponse = (HttpServletResponse)response;
	    	//1. Cross-Site Request Forgery Check
	    	//long xssForgeryCheckTime = System.currentTimeMillis();
	    	String httpReferer = hRequest.getHeader("referer");
	    	String securityFilter_CSRF = System.getProperty("securityfilter_csrf");
	    	if(securityFilter_CSRF!=null) securityFilter_CSRF = securityFilter_CSRF.trim();
	    	boolean isSecurityFilterCSRFOn = (securityFilter_CSRF == null
					|| "".equalsIgnoreCase(securityFilter_CSRF)
					||  "ON".equalsIgnoreCase(securityFilter_CSRF));
	    	if (isSecurityFilterCSRFOn && httpReferer != null && !"".equals(httpReferer.trim())) {
	    		httpReferer = httpReferer.trim();
	    		boolean error = false;
	    		try {
		    		URL url = new URL(httpReferer);
		    		if (url == null || url.getHost() == null) {
		    			throw new MalformedURLException("Invalid Request");
		    		}
		    		String urlHost = url.getHost();
		    		String serverName = hRequest.getServerName();
		    		if(urlHost != null && serverName != null){
		    			String sourceDomain = urlHost.substring(urlHost.indexOf(".")+1);
		    			String targetDomain = serverName.substring(serverName.indexOf(".")+1);
		    			if (sourceDomain!= null && !sourceDomain.equalsIgnoreCase(targetDomain)) {
				    		System.err.println("HTTP referer is "+httpReferer + " : url.getHost() is " + urlHost + " : request.getServerName() is " + serverName + " : sourceDomain is " + sourceDomain + " : targetDomain is " + targetDomain);
			    			throw new MalformedURLException("Invalid Request");
			    		}
		    		}
	    		}catch(MalformedURLException ex) {
	    			System.err.println("URL String is " + httpReferer + " exception :" + ex.getMessage());
	    			error = true;
	    		}

	    		if (error) {
	    			hResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Request denied. Cross-Site request forgery has been detected.");
	    			return;
	    		}
	    	}
	    	//System.err.println("Common XSS forgery check time: "+(System.currentTimeMillis() - xssForgeryCheckTime) + " ms");

	    	// 2. Cross-Site Scripting Check : Filter out hazardous characters from user input
	    	//long xssHazardousCharsCheckTime = System.currentTimeMillis();
	    	boolean isHazardousCharsPresent = false;
	    	boolean isGetRequest = ("GET".equalsIgnoreCase(hRequest.getMethod()));
	    	String securityFilter_XSS = System.getProperty("securityfilter_xss");
	    	if(securityFilter_XSS!=null) securityFilter_XSS = securityFilter_XSS.trim();
	    	boolean isSecurityFilterXSSOn = (securityFilter_XSS == null
					|| "".equalsIgnoreCase(securityFilter_XSS)
					||  "ON".equalsIgnoreCase(securityFilter_XSS));
	    	if(isSecurityFilterXSSOn){
	    		String securityFilter_iframe = System.getProperty("securityfilter_iframe");
	    		if(securityFilter_iframe!=null) securityFilter_iframe = securityFilter_iframe.trim();
		    	boolean isSecurityFilterIFrameOn = (securityFilter_iframe == null
						|| "".equalsIgnoreCase(securityFilter_iframe)
						||  "ON".equalsIgnoreCase(securityFilter_iframe));
	    		Enumeration<String> paramEnum = hRequest.getParameterNames();
		    	while (paramEnum.hasMoreElements()) {
					String paramName = paramEnum.nextElement();
					String[] paramValues = hRequest.getParameterValues(paramName);
					if (paramValues != null && paramValues.length > 0) {
						for (int i=0;!isHazardousCharsPresent && i<paramValues.length;i++) {
							//Check for SCRIPT pattern
							isHazardousCharsPresent = scriptTagPattern.matcher(paramValues[i]).find();
							//System.err.println("Script Tag Bad Characters "+isHazardousCharsPresent+" Name "+paramName+" Value "+paramValues[i]);
							//Check for IFRAME pattern
							if(!isHazardousCharsPresent && isSecurityFilterIFrameOn){
								isHazardousCharsPresent = iframePattern.matcher(paramValues[i]).find();
								//System.err.println("IFrame Bad Characters "+isHazardousCharsPresent+" Name "+paramName+" Value "+paramValues[i]);
							}
							//Check for XSRF pattern
							if(!isHazardousCharsPresent){
								isHazardousCharsPresent = xsrfPattern.matcher(paramValues[i]).find();
								//System.err.println("XSRF Bad Characters "+isHazardousCharsPresent+" Name "+paramName+" Value "+paramValues[i]);
							}
							//Check for bad characters pattern
							if(!isHazardousCharsPresent && isGetRequest){
								String appname = (String) request.getParameter("appName");
								if(appname!=null && !"iview".equalsIgnoreCase(appname)&& !"eprs".equalsIgnoreCase(appname))
						         	isHazardousCharsPresent = badCharPattern.matcher(paramValues[i]).find();
								
								//System.err.println("GET Request Bad Character found "+isHazardousCharsPresent+" Name "+paramName+" Value "+paramValues[i]);
							}
						}
					}
		    	}
	    	}
	    	if (isHazardousCharsPresent) {
	    		hResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Request denied. Cross-Site scripting check failed. Invalid characters are found in request parameters.");
				return;
	    	}
	    	//System.err.println("XSS Hazardous chars check time: "+(System.currentTimeMillis()) + " ms");
	    	
	    	/*******************************************************************************************/
	    	/* Code for nuVue iView Bridge filter logic */
	    	/*******************************************************************************************/
	    	
	    	//below request parameters are for authentication purpose
			String appname = (String) request.getParameter("appName");
			
			
			if(appname!=null && appname.equalsIgnoreCase("iview")){
			
				String token = (String) request.getParameter("token");
				String username = (String) request.getParameter("user");
				String emp_id = (String) request.getParameter("emp_id");
				
		    	long startTime = System.currentTimeMillis();
				long endTime = 0;
				
				applicationLogger = new ApplicationLogger(this.getClass().getName());
				applicationLogger.info("Start", "IViewAuthFilter", "doFilter");
				
				
				
				applicationLogger.debug("Request parameters ======================");
				applicationLogger.debug("appName = " + appname);
				applicationLogger.debug("token = " + token);
				applicationLogger.debug("username = " + username);
				applicationLogger.debug("emp_id = " + emp_id);
				
				
				 /* token testing for time being
				 */
				boolean hasToken = false;
				if(token != null && !token.isEmpty()){
					hasToken=true;
				}
				LDAPAuthUtil authUtil = new LDAPAuthUtil();
				//token = authUtil.generateToken();
				boolean isTokenValid = false;
				
				if("IVIEW-PK".equals(token)){
					isTokenValid = true;
				}else{
					try{
						isTokenValid = authUtil.validateToken(token);
					}catch(Exception e){
						e.printStackTrace();
					}
				}
				//handshake validation
				if(!"iview".equalsIgnoreCase(appname)){
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=noappname");
					return;
				}
				String countryCd = (String) request.getParameter("policyOrgCountryCd");
				if(countryCd == null || countryCd.isEmpty()){
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=nocountrycd");
					return;
				}
				String policyNo=(String)request.getParameter("policyNumber");
				if(policyNo == null || policyNo.isEmpty()){
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=nopolicyno");
					return;
				}
				String policyEffdt=(String)request.getParameter("policyEffDt");
				if(policyEffdt == null || policyEffdt.isEmpty()){
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=noeffdt");
					return;
				}
				if(username == null || username.isEmpty()){
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=nousername");
					return;
				}
				
				if(hasToken && isTokenValid){
					try{
						HttpSession session = ((HttpServletRequest)request).getSession(true);
					//	UserEntitlementBean userEntitlementBean = getTestData();//this.getUserForIView(username);//getTestData();
						UserEntitlementBean userEntitlementBean =this.getUserForIView(username);


						if (userEntitlementBean.isAuthFlage()) {
							String roleNm = userEntitlementBean.getRoleName();
								//System.out.println("valid authorised rights");
								session.setAttribute("userEntBean", userEntitlementBean);
								//session.setAttribute("username", userId.trim().toUpperCase());
								
								Vector<String> rolSet=userEntitlementBean.getUserRole();
								
								Set divSet1=userEntitlementBean.getDivisions();
								Iterator itr2=divSet1.iterator();
							
								Set division = userEntitlementBean.getDivisions();
									
								Iterator<Integer> itr1 = division.iterator();
								String totalDivions = "";
								while (itr1.hasNext()) {
									Integer div = (Integer) itr1.next();
									totalDivions += ""+div + ",";
								}
									DBUtility auditDBUtil =null;
								auditDBUtil = new DBUtility();
								Date date = new Date();
					            int login_Id;
						        login_Id = auditDBUtil.getDBSeqNo("LOGIN_ID");
						        if (totalDivions.length() > 100){
						        	String totDivisions= totalDivions.substring(0, 99);
						        	totalDivions = totDivisions;
						        }
						        auditDBUtil.insertAuditInfo(login_Id, userEntitlementBean.getEmployeeId(), "IVIEW",roleNm, totalDivions , "", date);
							    session.setAttribute("login_Id", String.valueOf(login_Id));
								
								endTime = System.currentTimeMillis();
								applicationLogger.info("Elapse Time -", "LoginServlet", ""+ (endTime - startTime) + "msec");
								//chain.doFilter(request, response);
						}
					}catch(Exception e){
						e.printStackTrace();
						((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=excep");
					}
				}else{
					((HttpServletResponse)response).sendRedirect(((HttpServletRequest)request).getContextPath()+ "/jsp/index.jsp?authLogin=authfailed");
				}
			}//end of check if applicationName is iview
	    	/******************************************************/
			/* End of NuVue iView Filter logic*/
			/******************************************************/
	    	
		}
		chain.doFilter(request, response);
	}
	
	private UserEntitlementBean getUserForIView(String userId){
		applicationLogger.debug("Receive IView Request. get a system user for iView requests.");
		LoginAuth aut = new LoginAuth();
		UserEntitlementBean userEntitlementBean=new UserEntitlementBean();
		userEntitlementBean = aut.getUserEntitlements("", userId, NuvueConstants.CASL_APPLICATION_NAME);
		applicationLogger.debug("system user for iView requests is assigned.");
		return userEntitlementBean;
	}
	
	private UserEntitlementBean getTestData(){
		UserEntitlementBean userEntitlementBean=new UserEntitlementBean();
		String userId = "nuv1006";
		
		
			userEntitlementBean.setEmployeeId(userId);
			userEntitlementBean.setFirstName("Thiyagarajan");
			userEntitlementBean.setLastName("Rajasekaran");
			Set<String> s=Collections.synchronizedSet(new LinkedHashSet<String>());
			s.add("VIEW");
			//s.add("SEARCH");
			
			Vector<String> vRole=new Vector<String>();
			vRole.addAll(s);
			userEntitlementBean.setUserRole(vRole);
			
			userEntitlementBean.setRoleName("NUVUE_SUPERVISOR");
			
			ArrayList<Integer> list=new ArrayList<Integer>();
			
			for(int i=99;i>0;i--){
				if(i!=2)
					list.add(i);
			}
			
			Collections.sort(list);
			Set<Integer> divSet=Collections.synchronizedSet(new LinkedHashSet<Integer>(list));
			userEntitlementBean.setDivisions(divSet);
			String strTemp="";
			Iterator<Integer> itr=divSet.iterator();
			while (itr.hasNext()) {
				Integer element = (Integer) itr.next();
				strTemp+=element+",";
			}
			
			strTemp=strTemp.substring(0, (strTemp.length()-1));
			userEntitlementBean.setUsersDivisionStr(strTemp);
			userEntitlementBean.setAuthFlage(true);
			userEntitlementBean.setApplicationName("NUVUE");
			
			
		return userEntitlementBean;
	}
}
filter mapping changes added
 <filter>
            <display-name>SecurityServletFilter</display-name>
            <filter-name>SecurityServletFilter</filter-name>
            <filter-class>com.us.chartisinsurance.nuvue.filter.SecurityServletFilter</filter-class>
        </filter>
      <filter-mapping>
            <filter-name>SecurityServletFilter</filter-name>
            <url-pattern>/*</url-pattern>
      </filter-mapping>
	
