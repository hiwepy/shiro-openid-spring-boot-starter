package org.apache.shiro.spring.boot.openid.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;

/**
 * Openid Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class OpenidStatefulAuthorizingRealm extends AbstractAuthorizingRealm{

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return OpenidAccessToken.class;// 此Realm只支持OpenidAccessToken
	}
	
}
