package com.example.helloworld.resources;

import javax.jws.WebMethod;
import javax.jws.WebService;

@javax.jws.WebService(
        name = "AddNumbersPortType",
        serviceName = "AddNumbersService",
        targetNamespace = "http://duke.example.org")
@javax.jws.soap.SOAPBinding(
        style = javax.jws.soap.SOAPBinding.Style.DOCUMENT,
        use = javax.jws.soap.SOAPBinding.Use.LITERAL,
        parameterStyle = javax.jws.soap.SOAPBinding.ParameterStyle.WRAPPED)
public class Calculator {
    @WebMethod
    public int Add(int a, int b) {
        return a + b;
    }
}
