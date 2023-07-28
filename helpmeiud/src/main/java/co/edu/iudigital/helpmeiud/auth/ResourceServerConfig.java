package co.edu.iudigital.helpmeiud.auth;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

/**
 * @author josaj
 *
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{


	// protección del lado de oath2
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				//se parte desde rutas más específicas a mas generales o genéricas
				// urls abiertas sin autenticación ni autorización
				// pero lo haremos más sencillo con anotaciones @Secured
				.antMatchers(HttpMethod.GET, "/delitos").permitAll()

				.antMatchers(HttpMethod.POST, "/usuarios/signup**").permitAll()
				.antMatchers(HttpMethod.OPTIONS, "/usuarios/signup**").permitAll()

				.antMatchers(HttpMethod.GET, "/casos", "/casos/caso/**").permitAll()
				// nivel 2: AUTORIZACIONES ESPECÍFICAS (SOBREESCRIBE LA GENÉRICA CORRESPONDIENTE)
				.antMatchers(HttpMethod.GET, "/usuarios/uploads/img/**").permitAll()
				//.antMatchers(HttpMethod.POST, "/usuarios/upload").hasAnyRole("USER", "ADMIN")
				//.antMatchers(HttpMethod.DELETE, "/delitos/delito/{id}").hasRole("ADMIN")
				// nivel 1: genéricas
				//.antMatchers(HttpMethod.POST, "/delitos").hasAnyRole("ADMIN")//otra forma es con @Secured en el controller
				//.antMatchers(HttpMethod.POST, "/employees").hasRole("ADMIN") or hasAnyRole
				.anyRequest().authenticated()// las rutas no especificadas, serán para usuarios autenticados

				.and()

				.cors().configurationSource(corsConfigurationSource())

				.and()
				.csrf().disable();

	}

	//---------------------------- 2--------------------

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://127.0.0.1:3000"));
		config.setAllowedMethods(Arrays.asList("GET", "PUT", "POST", "PATCH", "DELETE", "OPTIONS"));
		config.setAllowCredentials(true);//permitir credenciales
		//config.setAllowedOriginPatterns(Arrays.asList("*"));
		config.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));//"Content-Type", "Authorization"
		//config.addExposedHeader("Authorization");

		//registramos la configuración
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);// para todas las rutas del back
		return source;
	}

	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter(){
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);// dar un orden bajo: entre más bajo el orden, mayor la precedencia 
		// como es el filtro más alto es sufiente para aplicar a todos los controllers
		return bean;
	}
}
