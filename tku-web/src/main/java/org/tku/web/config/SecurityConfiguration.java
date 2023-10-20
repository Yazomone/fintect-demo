package org.tku.web.config;


import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Collection;

@Log4j2
@EnableWebSecurity
@Configuration
public class SecurityConfiguration {
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // WebSecurityCustomizer是一个类似于Consumer<WebSecurity>的接口，函数接受一个WebSecurity类型的变量，无返回值
        // 此处使用lambda实现WebSecurityCustomizer接口，web变量的类型WebSecurity，箭头后面可以对其进行操作
        // 使用requestMatchers()代替antMatchers()
        return (web) -> {
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.formLogin(httpSecurityFormLoginConfigurer -> {
            httpSecurityFormLoginConfigurer.loginPage("/login").defaultSuccessUrl("/").usernameParameter("userName").passwordParameter("password").failureHandler((request, response, exception)->{
                log.error("密碼錯誤");
                response.sendRedirect("/login?error=failed");
            });
        });

        http.authorizeHttpRequests(registry -> {
            // 定義哪些URL需要被保護、哪些不需要被保護
            registry.requestMatchers("/web/**").authenticated()
                    .anyRequest().permitAll();

        });

        http.csrf(httpSecurityCsrfConfigurer-> {
        });

        http.exceptionHandling(configurer -> {
            configurer.authenticationEntryPoint((request, response, authException) -> {
                log.error("未登入 : "+ authException.getMessage());
                response.sendRedirect("/login?error=unauth");
            });
        });

        http.headers(configurer -> {
            configurer.cacheControl(HeadersConfigurer.CacheControlConfig::disable);
            configurer.contentSecurityPolicy(httpSecurityHeadersConfigurerContentSecurityPolicyConfig -> {
                httpSecurityHeadersConfigurerContentSecurityPolicyConfig.policyDirectives("default-src 'self';");
            });
            configurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny);
        });

        http.logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer.logoutSuccessHandler((request, response, authentication) -> {
                    log.debug("logout");
                })
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID").invalidateHttpSession(true).clearAuthentication(true).permitAll());

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        daoAuthenticationProvider.setUserDetailsService(username -> {
            return new UserDetails() {
                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return AuthorityUtils.commaSeparatedStringToAuthorityList("USER");
                }

                @Override
                public String getPassword() {
                    return bCryptPasswordEncoder().encode("1qaz@WSX");
                }

                @Override
                public String getUsername() {
                    return username;
                }

                @Override
                public boolean isAccountNonExpired() {
                    return true;
                }

                @Override
                public boolean isAccountNonLocked() {
                    return true;
                }

                @Override
                public boolean isCredentialsNonExpired() {
                    return true;
                }

                @Override
                public boolean isEnabled() {
                    return true;
                }
            };
        });
        return daoAuthenticationProvider;
    }

//    @Autowired
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
}