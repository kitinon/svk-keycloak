import { Issuer } from 'openid-client'
import wcmatch from 'wildcard-match'
import log from 'loglevel'
import { decrypt, encrypt } from "zencrypt"

log.setLevel(process.env.loglevel || 'error')

// Utilities functions  
const redirect = (url, headers) => {
  headers ||= {}
  headers.Location = url
  return new Response(null, { status: 302, headers})
}
//#Source https://bit.ly/2neWfJ2 
const URL_Join = (...args) => args
  .join('/')
  .replace(/[\/]+/g, '/')
  .replace(/^(.+):\//, '$1://')
  .replace(/^file:/, 'file:/')
  .replace(/\/(\?|&|#[^!])/g, '$1')
  .replace(/\?/g, '&')
  .replace('&', '?')

export default ({
  realm,
  client_id,
  client_secret,
  keycloak_server,
  use_cookie,
  cookie_name,
  login_path,
  unprotected_paths,
  scopes,
}) => {
  login_path ||= '/'
  cookie_name ||= 'e17c17164bf9d72b565f62738bd5426f'
  scopes ||= ''

  // Get a promise to Keycloak server info
  const issuer = URL_Join(keycloak_server, `/realms/${realm}`)
  log.debug(`issuer: ${issuer}`)
  const issuer_discovery = Issuer.discover(issuer)

  let client

  return async function( {event, resolve} ) {
    const url = new URL(event.request.url)
    const pathmatch = spec => wcmatch(spec)(url.pathname)
    const { Client, metadata } = await issuer_discovery
    const origin = url.origin
    const redirect_url = origin+'/'
    log.debug(`redirect_url: ${redirect_url}`)

    client = client || new Client({
      client_id,
      client_secret,
      response_types: ['code'],
      redirect_uris: [ redirect_url ]
    })

    let id_token
    let cookie_exist

    const get_access_token = async ()=>{
      let access_token
      // First, check cookie
      if (use_cookie) {
        log.debug('use_cookie is true, checking cookie.')
        const cookie = event.cookies.get(cookie_name)
        if (cookie) {
          cookie_exist = true
          access_token = await decrypt(cookie, client_secret)
          if (access_token) return access_token
        }
      }
      // Second, check authorization header
      const authorization_header = event.request.headers.get('authorization')
      if (authorization_header) {     // authorization header attached
        log.debug('Authorization header found.')
        const [bearer, token, others] = authorization_header.split(' ')
        if (bearer === 'Bearer' && others == null) {
          access_token = token
          if (access_token) return access_token
        } else {
          throw new Error('Improper Authorization header.')
        }
      }
      // Thrid, check form data
      if (event.request.method === 'POST') {
        log.debug('Checking authorization field in form.')
        const request = event.request.clone()
        const authorization_feilds = ([ ...await request.formData() ]
        .filter(
          kv => kv[0].toLowerCase() === 'authorization'
        ))
        if (authorization_feilds.length > 0) access_token = authorization_feilds[0][1]
        if (access_token) return access_token
      }
      // Last,check if authenticating
      if (event.request.method == 'GET' && url.pathname == '/' ) {
        const params = client.callbackParams(event.request)
        const keys = Object.keys(params)
        if (keys.includes('code')) {  // authenticating
          log.debug('This is a callback request from an authenication server.')
          let tokenSet = await client.callback(redirect_url, params)
          access_token = tokenSet.access_token
          id_token = tokenSet.id_token
          if (access_token) return access_token
        }
      }
    }

    try {
      const access_token = await get_access_token()
      if (access_token) {
        const claims = await client.introspect(access_token)

        let logout_url
        if (id_token) {
          logout_url = metadata.end_session_endpoint + '?id_token_hint=' + id_token + '&post_logout_redirect_uri=' + origin
          log.debug(`logout_url=${logout_url}`)
        }

        event.locals.auth = { access_token, claims, logout_url }
        if (use_cookie && !cookie_exist) {
          event.cookies.set(cookie_name, await encrypt(access_token, client_secret), { path: '/', secure: false })
        }
        if (url.pathname == "/logout") {
          event.cookies.delete(cookie_name, { path: '/', secure: false });
        }
        return resolve(event)
      }
    } catch (err) {
      log.error(`Access token verification failed: ${err.message || err}`)
      const delCookie = {
        "Set-Cookie": event.cookies.serialize(cookie_name, "", { path: "/", secure: false, httpOnly: true, expires: new Date(0)})
      }
      return redirect(origin, delCookie)
    }

    // check for free-pass
    if (pathmatch(unprotected_paths)) {
      event.locals.auth = { login_path }
      return resolve(event)
    }

    // Do auto-login if path matches login_path
    if (event.request.method == 'GET' && wcmatch(login_path)(url.pathname)) {
      const authorization_url = client.authorizationUrl({
        scope: ('openid ' + scopes).split(' ').filter(s=>s.length).join(' '),
        response_type: 'code',
        //response_mode: 'query',
      })
      log.debug(`authorization_url: ${authorization_url}`)
      return redirect(authorization_url)
    }

    // finally, it's unauthorized
    return new Response('Unauthorized access.', {status: 401})
  }
}

export const getSA_access_token = async ({
  realm,
  client_id,
  client_secret,
  keycloak_server
}) => {
  keycloak_server ||= DEFAULT_KEYCLOAK_SERVER
  const issuer = URL_Join(keycloak_server, `/realms/${realm}`)
  const { token_endpoint } = (await Issuer.discover(issuer)).metadata
  log.debug(`token_endpoint: ${token_endpoint}`)
  const credential = btoa(`${client_id}:${client_secret}`)

  return fetch(token_endpoint, {
    method: 'POST',
    headers: {
      "Authorization" : `Basic ${credential}`,
      "Content-Type" : "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  })
  .then(res=>{
    if (200 >= res.status && res.status <= 299) { return res.json() }
    throw new Error(res.statusText)
  })
  .then(data=>data.access_token)
}
