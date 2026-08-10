package org.apache.shiro.spring.boot.openid;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.junit.jupiter.api.Test;

/**
 * Tests for OpenidStatelessPrincipal and OpenidStatelessPrincipalRepository.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
class OpenidPrincipalTest {

    @Test
    void openIdStatelessPrincipalShouldBeCreatable() {
        OpenidStatelessPrincipal principal = new OpenidStatelessPrincipal();
        assertThat(principal).isNotNull();
    }

    @Test
    void principalRepositoryShouldReturnAuthenticationInfo() {
        OpenidStatelessPrincipalRepository repository = new OpenidStatelessPrincipalRepository();
        AuthenticationToken token = new OpenidAccessToken("192.168.1.1");
        AuthenticationInfo info = repository.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(OpenidStatelessPrincipal.class);
    }

    @Test
    void principalRepositoryShouldHandleNullHost() {
        OpenidStatelessPrincipalRepository repository = new OpenidStatelessPrincipalRepository();
        AuthenticationToken token = new OpenidAccessToken(null);
        AuthenticationInfo info = repository.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
    }
}
