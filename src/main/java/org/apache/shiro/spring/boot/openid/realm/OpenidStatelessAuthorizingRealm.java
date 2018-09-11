package org.apache.shiro.spring.boot.openid.realm;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.OpenidStatelessPrincipal;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Openid Stateless AuthorizingRealm
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class OpenidStatelessAuthorizingRealm extends AbstractAuthorizingRealm<OpenidStatelessPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return OpenidAccessToken.class;// 此Realm只支持OpenidAccessToken
	}
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		OpenidStatelessPrincipal principal = (OpenidStatelessPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		info.setRoles(principal.getRoles());
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
