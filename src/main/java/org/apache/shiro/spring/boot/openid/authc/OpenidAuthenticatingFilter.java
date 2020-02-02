/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.openid.authc;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter;
import org.apache.shiro.spring.boot.openid.OpenidDiscoveryInformationProvider;
import org.apache.shiro.spring.boot.openid.exception.OpenidConsumerException;
import org.apache.shiro.spring.boot.openid.exception.OpenidDiscoveryException;
import org.apache.shiro.spring.boot.openid.exception.OpenidMessageException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.FetchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.alibaba.fastjson.JSONObject;

/**
 * Openid 认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class OpenidAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(OpenidAuthenticatingFilter.class);

	/**
     * The default redirect URL to where the user will be redirected on access denied.  The value is {@code "/"}, Shiro's
     * representation of the web application's context root.
     */
    public static final String DEFAULT_REDIRECT_URL = "/";

    /**
     * The URL to where the user will be redirected on access denied.
     */
    private String redirectUrl = DEFAULT_REDIRECT_URL;
    
    private ConsumerManager consumerManager = new ConsumerManager();
    private OpenidDiscoveryInformationProvider discoveryInformationProvider;
    
	public OpenidAuthenticatingFilter() {
		super();
	}
	
	@SuppressWarnings("rawtypes")
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			
			if (LOG.isTraceEnabled()) {
				LOG.trace("Login submission detected.  Attempting to execute login.");
			}
			
			try {
				
				HttpServletRequest httpRequest = WebUtils.toHttp(request);
				HttpServletResponse httpResponse = WebUtils.toHttp(response);
				
				UriComponentsBuilder builder = ServletUriComponentsBuilder.fromRequest(httpRequest);
				
				// configure the return_to URL where your application will receive  
				// the authentication responses from the OpenID provider  
				String returnUrl = builder.path(getRedirectUrl()).build().toUriString();  
				  
				// --- Forward proxy setup (only if needed) ---  
				// ProxyProperties proxyProps = new ProxyProperties();  
				// proxyProps.setProxyName("proxy.example.com");  
				// proxyProps.setProxyPort(8080);  
				// HttpClientFactory.setProxyProperties(proxyProps);  
				
				// perform discovery on the user-supplied identifier  
				List discoveries = consumerManager.discover(getLoginUrl());  
  
				// attempt to associate with the OpenID provider  
				// and retrieve one service endpoint for authentication  
				DiscoveryInformation discovered = consumerManager.associate(discoveries);  
				  
				// store the discovery information in the user's session  
				discoveryInformationProvider.setDiscovered(httpRequest, httpResponse, discovered);
  
				// obtain a AuthRequest message to be sent to the OpenID provider  
				AuthRequest authReq = consumerManager.authenticate(discovered, returnUrl);  
  
				// attribute Exchange  
				FetchRequest fetch = FetchRequest.createFetchRequest();  
				fetch.addAttribute("email", "http://axschema.org/contact/email", true);  
				fetch.addAttribute("firstName", "http://axschema.org/namePerson/first", true);  
				fetch.addAttribute("lastName", "http://axschema.org/namePerson/last", true);  
				  
				// attach the extension to the authentication request  
				authReq.addExtension(fetch);  
				
				if (!discovered.isVersion2()) {  
				    // Option 1: GET HTTP-redirect to the OpenID Provider endpoint  
				    // The only method supported in OpenID 1.x  
				    // redirect-URL usually limited ~2048 bytes  
					httpResponse.sendRedirect(authReq.getDestinationUrl(true));  
					// WebUtils.issueRedirect(httpRequest, httpResponse, authReq.getDestinationUrl(true), null, false);
				} else {  
				    // Option 2: HTML FORM Redirection (Allows payloads >2048 bytes)  
					httpResponse.sendRedirect(authReq.getDestinationUrl(true));  
					// WebUtils.issueRedirect(httpRequest, httpResponse, authReq.getDestinationUrl(true), null, false);
				}
				return false;
			} catch (DiscoveryException e) {
				return onLoginFailure(null, new OpenidDiscoveryException(e), request, response);
			} catch (MessageException e) {
				return onLoginFailure(null, new OpenidMessageException(e), request, response);
			} catch (ConsumerException e) {
				return onLoginFailure(null, new OpenidConsumerException(e), request, response);
			} catch (AuthenticationException e) {
				return onAccessFailure(null, e, request, response);
			} catch (Exception e) {
				return onLoginFailure(null, new AuthenticationException(e), request, response);
			}
		}
		// 2、未授权情况
		else {
			
			String mString = "Attempting to access a path which requires authentication. ";
			if (LOG.isTraceEnabled()) { 
				LOG.trace(mString);
			}
			
			// Ajax 请求：响应json数据对象
			if (WebUtils.isAjaxRequest(request)) {
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
			}
			// 普通请求：重定向到未授权提示页
			WebUtils.issueRedirect(request, response, getUnauthorizedUrl());
			return false;
		}
	}
	
	/**
     * Returns the URL to where the user will be redirected on access denied.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @return the URL to where the user will be redirected on access denied.
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Sets the URL to where the user will be redirected on access denied.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @param redirectUrl the url to where the user will be redirected on access denied
     */
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
	
}
