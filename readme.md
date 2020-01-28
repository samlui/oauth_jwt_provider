# MuleSoft - JWT Generation with Muesoft OAuth2 Provider Example

This example Mule Application is meant to extend Mulesoft OAuth Provider for the generation of JWT token which can be used by the JWT policy in Mule Anypoint runtime manager.

The original Mulesoft OAuth2 Provider module allows a Mule runtime engine (Mule) app to be configured as an Authentication Manager in an OAuth2 dance. With this role, the application will be able to authenticate previously registered clients, grant tokens, validate tokens, or register and delete clients, all during the execution of a flow.


This project provides examples to generate and validate a token and register a client.

<img src="https://raw.githubusercontent.com/samlui/oauth_jwt_provider/master/src/main/resources/img/interaction.png" width="400"/>

# Prerequisites

* Anypoint Studio 7.4.1
* Mule EE 4.2.2

# Resources

* [OAuth Provider Module Reference](https://docs.mulesoft.com/connectors/oauth/oauth2-provider-documentation-reference#configurations)


---

_Authentication flow_

<img src="https://raw.githubusercontent.com/samlui/oauth_jwt_provider/master/src/main/resources/img/authentication.png" width="400"/>




_Authentication Request_

<img src="https://raw.githubusercontent.com/samlui/oauth_jwt_provider/master/src/main/resources/img/auth_request.png" width="400"/>

```
curl --location --request POST 'http://localhost:8081/access-token?grant_type=password&client_id=<client_id>&client_secret=<client_secret>&scope=READ&password=user1&username=user1' \
--header 'Content-Type: application/json' \
--data-raw ''
```


*Input to Custom Authentication Flow*
```
%dw 2.0
output application/java
---
{
	user: "user1",
	pass: "user1"
}
```


_Authentication Response_

<img src="https://raw.githubusercontent.com/samlui/oauth_jwt_provider/master/src/main/resources/img/auth_result.png" width="400"/>


*Output from Custom Authentication Flow*
```
%dw 2.0
output application/java
---
{
	authenticated: true,
	custom_attributes: {
		id: "id1",
		ssd: "123-23-2234",
		aud: "www.mulesoft.com",
		scp1: "email",
		scp2: "openid"
	}
}
```
---

_JWT Result_

<img src="https://raw.githubusercontent.com/samlui/oauth_jwt_provider/master/src/main/resources/img/jwt.png" width="400"/>
