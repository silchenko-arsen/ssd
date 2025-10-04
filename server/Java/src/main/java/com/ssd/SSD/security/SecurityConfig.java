package com.ssd.SSD.security;

import com.ssd.SSD.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${ssd.domain}")
    private String domainOfFrontEnd;
    private final JwtRequestFilter jwtRequestFilter;
    private final UserRepository userRepository;

    @Autowired
    public SecurityConfig(UserRepository userRepository, JwtRequestFilter jwtRequestFilter) {
        this.userRepository = userRepository;
        this.jwtRequestFilter = jwtRequestFilter;

    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/auth/login", "api/auth/register", "api/auth/verify").permitAll()
                        .requestMatchers("/api/auth/admin/reg", "api/auth/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("/api/auth/admin/create/default").permitAll()

                        .requestMatchers("/api/projects/add", "api/projects/close/{id}", "api/projects/del/{id}",
                                "api/projects/join/").authenticated()
                        .requestMatchers("api/projects/admin/del/{id}", "api/projects/admin/close/{id}",
                                "api/projects/admin/setislegal", "api/projects/admin/toinspection").hasRole("ADMIN")
                        .requestMatchers("api/projects", "api/projects/filter", "api/projects/{id}").permitAll()

                        .requestMatchers("/api/memes/add", "/api/memes/del/{id}").authenticated()
                        .requestMatchers("/api/memes/admin/del/{id}", "api/memes/admin/memetoinspection",
                                "api/memes/admin/setislegal").hasRole("ADMIN")
                        .requestMatchers("/api/memes/{id}", "api/memes").permitAll()

                        .requestMatchers("/api/gallery/admin/del/{id}", "api/gallery/admin/add").hasRole("ADMIN")
                        .requestMatchers("/api/gallery/{id}", "api/gallery").permitAll()

                        .requestMatchers("/api/news/admin/del/{id}", "api/news/admin/add").hasRole("ADMIN")
                        .requestMatchers("/api/news/{id}", "api/news").permitAll()

                        .requestMatchers("/api/document/admin/add",
                                "/api/document/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("/api/document/{id}", "api/document").permitAll()

                        .requestMatchers("/api/collective/admin/add",
                                "/api/collective/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("/api/collective/{id}", "api/collective").permitAll()

                        .requestMatchers("/api/useful-link/admin/add",
                                "/api/useful-link/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("api/useful-link", "api/useful-link/{id}").permitAll()

                        .requestMatchers("/api/course-link/admin/add",
                                "/api/course-link/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("api/course-link", "api/course-link/{id}").permitAll()

                        .requestMatchers("/api/announcement/admin/add",
                                "/api/announcement/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("api/announcement/all", "api/announcement/{id}", "api/announcement/in-order").permitAll()

                        .requestMatchers("/api/vacancy/admin/add",
                                "/api/vacancy/admin/del/{id}").hasRole("ADMIN")
                        .requestMatchers("api/vacancy", "api/vacancy/{id}").permitAll()

//                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()

                        .anyRequest().authenticated()
                )
                .formLogin(formlogin -> formlogin.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl(userRepository);
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true); // Дозволити cookie та авторизаційні заголовки

        // Дозволити будь-який порт на цьому домені
        configuration.addAllowedOriginPattern("http://host-176-36-217-137.b024.la.net.ua*");
        configuration.addAllowedOriginPattern("https://host-176-36-217-137.b024.la.net.ua*");

        configuration.addAllowedHeader("*"); // Дозволити всі заголовки
        configuration.addAllowedMethod("*"); // Дозволити всі методи (GET, POST, PUT, DELETE тощо)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Реєстрація конфігурації CORS
        return source;
    }


//    @Bean
//    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowCredentials(true); // Дозволити передачу cookie та авторизаційних заголовків
//
//        configuration.addAllowedOriginPattern("*"); // Дозволити всі походження
//        configuration.addAllowedHeader("*"); // Дозволити всі заголовки
//        configuration.addAllowedMethod("*"); // Дозволити всі методи (GET, POST, PUT, DELETE тощо)
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration); // Реєстрація конфігурації CORS
//        return source;
//    }

//    @Bean
//    public CorsFilter corsFilter() {
//        return new CorsFilter(corsConfigurationSource()); // Повертаємо фільтр
//    }
}
