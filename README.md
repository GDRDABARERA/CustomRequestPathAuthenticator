# CustomRequestPathAuthenticator
A simple sample for a custom request path authenticator

This is simialar to the request path authenticator in our WSO2 IS. But you can change the functionalities according to your use case. You can try out the sample in [1] with this customAuthenticator by changing below request


 curl -v -X POST -H  -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" -k -d "response_type=code&client_id=pmnWemzPeTbudjc_jXNRvf5x0Q0a&redirect_uri=http://localhost.com:8080/pickup-dispatch/oauth2client&scope=openid&prompt=none"  http://localhost:9763/oauth2/authorize?customsectoken=YWRtaW46YWRtaW4=


The response will be with the authorization code where you can call the token end point:
< Location: http://localhost.com:8080/pickup-dispatch/oauth2client?code=3ff56e8a-1683-3c79-b1fc-858037964f1e&session_state=5c5d544dcbedeea4c5e21ca842243f791dce31b2939f8bbb2a1b0fdebc2355f2.C4Gv492X-oa-K7iwysXFmQ





[1]https://docs.wso2.com/display/IS570/Basic+Auth+Request+Path+Authentication
