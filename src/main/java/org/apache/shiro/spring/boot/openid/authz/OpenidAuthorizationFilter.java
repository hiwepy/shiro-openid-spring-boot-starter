package org.apache.shiro.spring.boot.openid.authz;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.spring.boot.openid.OpenidDiscoveryInformationProvider;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.apache.shiro.subject.Subject;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Openid 授权 (authorization) 过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class OpenidAuthorizationFilter extends AbstracAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(OpenidAuthorizationFilter.class);
    
	private ConsumerManager consumerManager = new ConsumerManager();
    private OpenidDiscoveryInformationProvider discoveryInformationProvider;
    
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
        
		String email = null;  
        String lastName = null;  
        String firstName = null;  
          
		try {
			
			// extract the parameters from the authentication response  
            // (which comes in as a HTTP request from the OpenID provider)  
            ParameterList parameterList = new ParameterList(request.getParameterMap());  
  
            // retrieve the previously stored discovery information  
            DiscoveryInformation discovered = discoveryInformationProvider.getDiscovered(httpRequest, httpResponse);  
  
            // extract the receiving URL from the HTTP request  
            StringBuffer receivingURL = httpRequest.getRequestURL();  
            String queryString = httpRequest.getQueryString();  
            if (queryString != null && queryString.length() > 0) {  
                receivingURL.append("?").append(httpRequest.getQueryString());  
            }  
  
            // verify the response; ConsumerManager needs to be the same  
            // (static) instance used to place the authentication request  
            VerificationResult verification = consumerManager.verify(receivingURL.toString(), parameterList, discovered);  
  
            // examine the verification result and extract the verified  
            // identifier  
            Identifier verified = verification.getVerifiedId();  
            if (verified == null) {  
                throw new OpenIDException("");
            }
            
            AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();  
            
            if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
            	
                FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);  

                List emails = fetchResp.getAttributeValues("email");  
                email = (String) emails.get(0);  
                  
                List lastNames = fetchResp.getAttributeValues("lastName");  
                lastName = (String) lastNames.get(0);  
                  
                List firstNames = fetchResp.getAttributeValues("firstName");  
                firstName = (String) firstNames.get(0);  
                  
                LOG.debug("email: {}", email);  
                LOG.debug("lastName: {}", lastName);  
                LOG.debug("firstName: {}", firstName);  
            }  
            // success  
              
            // 在这里与安全框架集成 apache-shiro/spring-security  
            // 这里要根据相关的信息自己定义Principal  
	        
	        // Step 3、生成Token 
			AuthenticationToken actoken = new OpenidAccessToken(getHost(request));
			
			// Step 4、委托给Realm进行登录  
			Subject subject = getSubject(request, response);
			subject.login(actoken);
	        
			// Step 5、执行授权成功后的函数
			return onAccessSuccess(mappedValue, subject, request, response);
		} catch (AuthenticationException e) {
			//Step 6、执行授权失败后的函数
			return onAccessFailure(mappedValue, e, request, response);
		} 
	}
	
	/**
	 * TODO
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param mappedValue
	 * @param e
	 * @param request
	 * @param response
	 * @return
	 */
	@Override
	protected boolean onAccessFailure(Object mappedValue, Exception e, ServletRequest request,
			ServletResponse response) throws IOException {

		LOG.error("Host {} Openid Authentication Failure : {}", getHost(request), e.getMessage());
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		String mString = "Attempting to access a path which requires authentication. ";
		if (LOG.isTraceEnabled()) { 
			LOG.trace(mString);
		} 
		
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		data.put("message", mString);
		
		if (WebUtils.isAjaxRequest(httpRequest)) {
			/* AJAX 请求 403 未授权访问提示 */
			httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
			WebUtils.writeJSONString(httpResponse, data);
        } else {
        	// If subject is known but not authorized, redirect to the unauthorized URL if
			// there is one
			// If no unauthorized URL is specified, just return an unauthorized HTTP status
			// code
			String unauthorizedUrl = getUnauthorizedUrl();
			// SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen
			// due to response commit:
			if (StringUtils.hasText(unauthorizedUrl)) {
				WebUtils.issueRedirect(request, response, unauthorizedUrl);
			} else {
				WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Forbidden");
			}
        }
	 
		return false;
	}
	
}
