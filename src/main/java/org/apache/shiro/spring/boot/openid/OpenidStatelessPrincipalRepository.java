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
package org.apache.shiro.spring.boot.openid;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepositoryImpl;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;

/**
 * Openid Token Principal Repository
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class OpenidStatelessPrincipalRepository extends ShiroPrincipalRepositoryImpl {
	
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		OpenidAccessToken kissoToken = (OpenidAccessToken) token;
		
		ShiroPrincipal principal = new OpenidStatelessPrincipal();
		
		/*principal.setUserid(ssoToken.getId());
		principal.setUserkey(ssoToken.getId());
		principal.setRoles(Sets.newHashSet(StringUtils.tokenizeToStringArray(String.valueOf(ssoToken.getClaims().get("roles")))));
		principal.setPerms(Sets.newHashSet(StringUtils.tokenizeToStringArray(String.valueOf(ssoToken.getClaims().get("perms")))));
		*/
		return new SimpleAuthenticationInfo(principal, "", "kisso");
	}
	 
	
}
