package org.apache.shiro.spring.boot.openid.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;

/**
 * Openid Stateful AuthorizingRealm
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class OpenidStatefulAuthorizingRealm extends AbstractAuthorizingRealm{

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return OpenidAccessToken.class;// 此Realm只支持OpenidAccessToken
	}
	
}
