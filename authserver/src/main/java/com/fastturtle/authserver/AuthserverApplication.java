package com.fastturtle.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

	@Bean
	InMemoryUserDetailsManager inMemoryUserDetailsManager() {
		UserDetails one = User.withDefaultPasswordEncoder()
				.username("sjohnr")
				.roles("user")
				.password("pw")
				.build();

		UserDetails two = User.withDefaultPasswordEncoder()
				.username("divya")
				.authorities("admin")
				.password("pw")
				.build();

		return new InMemoryUserDetailsManager(one, two);
	}

}
