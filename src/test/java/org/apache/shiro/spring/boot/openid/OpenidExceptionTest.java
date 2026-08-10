package org.apache.shiro.spring.boot.openid;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.spring.boot.openid.exception.OpenidConsumerException;
import org.apache.shiro.spring.boot.openid.exception.OpenidDiscoveryException;
import org.apache.shiro.spring.boot.openid.exception.OpenidMessageException;
import org.junit.jupiter.api.Test;

/**
 * Tests for Openid exception classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
class OpenidExceptionTest {

    @Test
    void openIdConsumerExceptionShouldExtendAuthenticationException() {
        assertThat(new OpenidConsumerException()).isInstanceOf(AuthenticationException.class);
    }

    @Test
    void openIdConsumerExceptionShouldSupportMessage() {
        OpenidConsumerException ex = new OpenidConsumerException("test message");
        assertThat(ex.getMessage()).isEqualTo("test message");
    }

    @Test
    void openIdConsumerExceptionShouldSupportCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidConsumerException ex = new OpenidConsumerException(cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void openIdConsumerExceptionShouldSupportMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidConsumerException ex = new OpenidConsumerException("test message", cause);
        assertThat(ex.getMessage()).isEqualTo("test message");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void openIdDiscoveryExceptionShouldExtendAuthenticationException() {
        assertThat(new OpenidDiscoveryException()).isInstanceOf(AuthenticationException.class);
    }

    @Test
    void openIdDiscoveryExceptionShouldSupportMessage() {
        OpenidDiscoveryException ex = new OpenidDiscoveryException("test message");
        assertThat(ex.getMessage()).isEqualTo("test message");
    }

    @Test
    void openIdDiscoveryExceptionShouldSupportCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidDiscoveryException ex = new OpenidDiscoveryException(cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void openIdDiscoveryExceptionShouldSupportMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidDiscoveryException ex = new OpenidDiscoveryException("test message", cause);
        assertThat(ex.getMessage()).isEqualTo("test message");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void openIdMessageExceptionShouldExtendAuthenticationException() {
        assertThat(new OpenidMessageException()).isInstanceOf(AuthenticationException.class);
    }

    @Test
    void openIdMessageExceptionShouldSupportMessage() {
        OpenidMessageException ex = new OpenidMessageException("test message");
        assertThat(ex.getMessage()).isEqualTo("test message");
    }

    @Test
    void openIdMessageExceptionShouldSupportCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidMessageException ex = new OpenidMessageException(cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void openIdMessageExceptionShouldSupportMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OpenidMessageException ex = new OpenidMessageException("test message", cause);
        assertThat(ex.getMessage()).isEqualTo("test message");
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
