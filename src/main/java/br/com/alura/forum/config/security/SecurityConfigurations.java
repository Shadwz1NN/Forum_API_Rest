package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private AutenticacaoService autenticacaoService;
	
	@Override    // configuracoes de autenticacao
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(autenticacaoService).passwordEncoder(new BCryptPasswordEncoder()); //vai informar onde ta a classe com a logica de autenticacao
		
	}
	@Override  // configuracoes de autorizacao
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET, "/topicos").permitAll() //vai permitir o get do endereco /topicos
			.antMatchers(HttpMethod.GET, "/topicos/*").permitAll() //se chegar uma requisicao get para topicos/alguma coisa ele vai permitir
			.anyRequest().authenticated() // qualquer outra requisicao tem que autenticar; 
			.and().formLogin();  
	}
	@Override // configuracoes de recursos estaticos(javascript, css, imagens, etc)
	public void configure(WebSecurity web) throws Exception {
		
	}
	
	
}
