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
package org.apache.shiro.spring.boot.openid;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepository;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;

import com.google.common.collect.Sets;

/**
 * Kisso Token Principal Repository
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class OpenidStatelessPrincipalRepository implements ShiroPrincipalRepository<OpenidStatelessPrincipal>, UserInfoService {
	
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

	@Override
	public Set<String> getRoles(OpenidStatelessPrincipal principal) {
		return principal.getRoles();
	}

	@Override
	public Set<String> getRoles(Set<OpenidStatelessPrincipal> principals) {
		Set<String> sets = Sets.newHashSet();
		for (ShiroPrincipal principal : principals) {
			sets.addAll(principal.getRoles());
		}
		return sets;
	}

	@Override
	public Set<String> getPermissions(OpenidStatelessPrincipal principal) {
		return Sets.newHashSet(principal.getPerms());
	}

	@Override
	public Set<String> getPermissions(Set<OpenidStatelessPrincipal> principals) {
		Set<String> sets = Sets.newHashSet();
		for (ShiroPrincipal principal : principals) {
			sets.addAll(principal.getPerms());
		}
		return sets;
	}
	
	@Override
	public void doLock(OpenidStatelessPrincipal principal) {
		// do nothing
	}

	@Override
	public UserInfo getByUsername(String username) {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public UserInfo getByUsernameAndClientId(String username, String clientId) {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public UserInfo getByEmailAddress(String email) {
		// TODO Auto-generated method stub
		return null;
	}
	
}
