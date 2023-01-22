# svk-keycloak

svk-keycloak is a Sveltekit handle for authenticating with keycloak using OIDC authorization code flow.  It does not create any session and supports both using and not using cookie to store credential information (i.e. access token).
## Install
```
npm install svk-keycloak
```
## API
```
import auth, {getSA_access_token} from 'svk-keycloak'
```
- auth({...}) // return SvelteKit hooks' handle.
- getSA_access_token(...) // return an access token of a service account.

## handle function
In hooks.server.js
``` js
import auth from 'svk-keycloak'

export const handle = auth({
  realm: 'my_realm',
  client_id : 'test-svk-keycloak',
  client_secret : 'b16fa85f0916e1625c0d6f499a82be0f',
  keycloak_server: 'https://keycloak.example.com:8443',
  //use_cookie: false,
  //cookie_name: 'e17c17164bf9d72b565f62738bd5426f',
  //login_path: '/',
  unprotected_paths : [ '/public/*' ],
  //scopes: ''
})
```

Call the imported function (*auth* in this example) with an options obect to get a handle function.

### options
*realm*, *client_id* and *client_secret* are mandatory.
  
*keycloak_server* is mandatory.  There is no default value.

*use_cookie* is optional.  Default is false.  When true, the middleware will store access token in browser cookie.  The cookie will be encrypted.

*cookie_name* is optional.  Default is 'e17c17164bf9d72b565f62738bd5426f'.  This is the name of an access token cookie.

*login_path* is optional.  The default is '/'.  This is a path that when users navigate to, they will be redirect to a login page.

*unprotected_paths* is optional.  It is an array of wildcard matching paths that users are allowed to browse without logging in.  The default value is an empty array, i.e. all paths are protected (required login).  For details on matching syntax see https://www.npmjs.com/package/wildcard-match.

*scopes* is optional. The default is ''. Use to add client scope to the client i.e. "address phone" (separate scope with blank space).

## login procedure
While users have not logged in, **event.locals.auth** will contain one key - login_path where user can navigate to for redirecting to a login page.  

Once a user has sucessfully logged in, **event.locals.auth** will contain the following keys:
- *access_token* is user's access token to be used in Authorizatoin header of all futher (API) requests.
- *claims* is the payload part of the *access_token*.
- *logout_url* is a url that user can navigate to a logout page.

A *+layout.server.js* file should load event.locals.auth so that it will be available to the frontend (SvelteKit's pages).  See the demo application below for how this can be done.

On subsequence server requests, if *use_cookie* is not true, the front-end may send an access token via an authorization header in the form `'baerer <access_token>'`.  However, on these requests, *event.locals.auth.logout_url* will be undefined.  So, front-end should save *logout_url* from first successful login request for later use.

Apart from using authorization header, the middleware also supports sending an access token in a form (POST request) using field name `authorization`.

## getSA_access_token
In +server.js of an API route:
```js
import { getSA_access_token } from 'svk-auth'

export async function GET({ url, locals }) {
  const SA_access_token = await getSA_access_token({
    realm: 'my_realm',
    client_id : 'my_client',
    client_secret : '8a7090e35b9bce3f9cc113a54be346e8'
  })
  return new Response(SA_access_token)
}
```
In the above example, an API use getSA_access_token to return an access token for the service account of this client (application).  Note that if the client does not have a service account enabled in keycloak, this will cause an exception.

## Debugging
The package uses [loglevel](https://www.npmjs.com/package/loglevel) for error logging/debugging.  Set *loglevel* environment variable to one of the five levels - error, warn, info, debug, trace.  The default level is error.  See [loglevel](https://www.npmjs.com/package/loglevel)'s README for details.

## Demo applicaiton
`git clone https://github.com/kitinon/test-svk-keycloak.git`

## Source repository
`git clone https://github.com/kitinon/svk-keycloak.git`