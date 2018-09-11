/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.openid.authz;

import java.lang.reflect.Type;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.GrantedAuthority;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */

public class MITREidConnectUserInfoFilter extends AuthenticatingFilter {

	private Gson gson = new GsonBuilder()
			.registerTypeHierarchyAdapter(GrantedAuthority.class, new JsonSerializer<GrantedAuthority>() {
				@Override
				public JsonElement serialize(GrantedAuthority src, Type typeOfSrc, JsonSerializationContext context) {
					return new JsonPrimitive(src.getAuthority());
				}
			})
			.create();

	@Autowired (required = false)
	private UserInfoService userInfoService;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		// TODO Auto-generated method stub
		return super.preHandle(request, response);
	}


	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param request
	 * @param response
	 * @return
	 * @throws Exception
	 */
	
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}


	/**
	 * TODO
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param request
	 * @param response
	 * @return
	 * @throws Exception
	 */
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		// TODO Auto-generated method stub
		return false;
	}
	

}
