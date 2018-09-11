package org.apache.shiro.spring.boot.openid.realm;

import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.token.OpenidLoginToken;

/**
 * Openid Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class OpenidStatefulAuthorizingRealm extends AbstractAuthorizingRealm<ShiroPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return OpenidLoginToken.class;// 此Realm只支持KissoLoginToken
	}
	
}
