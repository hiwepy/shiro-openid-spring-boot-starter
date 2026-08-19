package org.apache.shiro.spring.boot.openid.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;

/**
 * Openid Stateful AuthorizingRealm
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class OpenidStatefulAuthorizingRealm extends AbstractAuthorizingRealm{

	@Override
	/**
	 * Returns the authentication token class.
	 *
	 * @return the authentication token class
	 */
	public Class<?> getAuthenticationTokenClass() {
		return OpenidAccessToken.class;// 此Realm只支持OpenidAccessToken
	}
	
}
