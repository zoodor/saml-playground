package com.example.helloworld;

import com.example.helloworld.health.TemplateHealthCheck;
import com.example.helloworld.resources.HelloWorldResource;
import com.example.helloworld.resources.SamlReceiver;
import com.yammer.dropwizard.Bundle;
import com.yammer.dropwizard.Service;
import com.yammer.dropwizard.config.Environment;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HelloWorldService extends Service<HelloWorldConfiguration> {
    public static void main(String[] args) throws Exception {
        new HelloWorldService().run(args);
    }

    private HelloWorldService() {
        super("hello-world");
        addBundle(new SoapBundle());

    }

    @Override
    protected void initialize(HelloWorldConfiguration configuration,
                              Environment environment) {
        final String template = configuration.getTemplate();
        final String defaultName = configuration.getDefaultName();
        environment.addResource(new HelloWorldResource(template, defaultName));
        environment.addResource(new SamlReceiver());
        environment.addHealthCheck(new TemplateHealthCheck(template));
    }

    private class SoapBundle implements Bundle {
        @Override
        public void initialize(Environment environment) {
            environment.addServlet(new com.sun.xml.ws.transport.http.servlet.WSServlet(), "/SOAP/*");
            environment.addServletListeners(new com.sun.xml.ws.transport.http.servlet.WSServletContextListener());
        }
    }

}

