<?php
/**
 * Authenticate using Google openid connect
 * 07/2014
 * @author Sylvain MEDARD
 * @version $Id$
 */
set_include_path(get_include_path() . PATH_SEPARATOR . '/var/idpgoogle/modules/authgoogleOIDC/extlibinc/src');

require_once 'Google/Client.php';
require_once 'Google/Service/Oauth2.php';

 
class sspmod_authgoogleOIDC_Auth_Source_GoogleOIDC extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'authgoogleOIDC:init';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'authgoogleOIDC:AuthId';
	
	const ISSUER = 'accounts.google.com';

	const federated_signon_certs_url = 'https://www.googleapis.com/oauth2/v1/certs';

	// Google Developper Console :
	// https://code.google.com/apis/console
	private $key;
	private $secret;
	
	// Redirect_uri
	private $linkback; 
	
	// Google_client
	private $client;
	// Google_Service_Oauth2
	//private $objOAuthService ;
	
		/**
		* Constructor for Google authentication source.
		*
		* @param array $info Information about this authentication source.
		* @param array $config Configuration.
		*/
		public function __construct($info, $config) {
			assert('is_array($info)');
			assert('is_array($config)');

			/* Call the parent constructor first, as required by the interface. */
			parent::__construct($info, $config);

			if (!array_key_exists('key', $config))
				throw new Exception('Google authentication source is not properly configured: missing [key]');

			$this->key = $config['key'];

			if (!array_key_exists('secret', $config))
				throw new Exception('Google authentication source is not properly configured: missing [secret]');

			$this->secret = $config['secret'];
			
			$this->linkback = SimpleSAML_Module::getModuleURL('authgoogleOIDC') . '/linkback.php';
			
			// Create Client
			$this->client = new Google_Client();
			$this->client->setApplicationName('Google gateway');
			$this->client->setClientId($this->key);
			$this->client->setClientSecret($this->secret);
			$this->client->setRedirectUri($this->linkback);
			
			$this->client->addScope('openid');
			$this->client->addScope('profile');
			$this->client->addScope('email');
			
		}
		
		/**
		* Log-in using Google OAuth2Login (OpenID Connect) platform
		* Documentation at : https://developers.google.com/accounts/docs/OAuth2Login
		*
		* @param array &$state Information about the current authentication.
		*/
		public function authenticate(&$state) {
			 
			$state[self::AUTHID] = $this->authId;
			$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);

			$this->client->getAuth()->setState($stateID);

			$authUrl = $this->client->createAuthUrl();
			SimpleSAML_Utilities::redirectTrustedURL($authUrl);
			
		}
	
		public function finalStep(&$state) {
			
			assert('is_array($state)');
			
			$auth_code = $state['authgoogleOIDC:code'];
				
			//Authenticate code from Google OAuth Flow
			//Add Access Token 
			if (isset($auth_code)) {
				// authenticate : use authorization code to get access_token and set it in the client
				$this->client->authenticate($auth_code);
				
				$token = $this->client->getAccessToken();
				SimpleSAML_Logger::debug('GOOGLE token :' . $token);
				
				$decoded = json_decode($token, true);
				
				$accesstoken = $decoded['access_token'];
				SimpleSAML_Logger::debug('GOOGLE access_token :' . $accesstoken);
				
				$idtoken = $decoded['id_token'];
				SimpleSAML_Logger::debug('GOOGLE id_token :' . $idtoken);
					
					
				// Decode & verify id_token with Google jwks_uri
				// http://openid.net/specs/openid-connect-basic-1_0.html#IDToken	
				$certs = $this->client->getAuth()->retrieveCertsFromLocation(self::federated_signon_certs_url);
				/*foreach($certs as $key=> $value){
					SimpleSAML_Logger::debug('certs keys:' . $key . ' value :  ' . $value);
				}*/
			
				$this->client->getAuth()->verifySignedJwtWithCerts($idtoken, $certs, $this->key, self::ISSUER);
			}

			//Get User Data 
			if ($this->client->getAccessToken()) {
				
				// Create OAuth2 service to get user info
				$objOAuthService = new Google_Service_Oauth2($this->client);
				
				$results = $objOAuthService->userinfo->get();
				foreach($results as $key => $value)
				{
					SimpleSAML_Logger::debug('Google userinfo : '.$key.' : '.$value);
				}
				$attributes = array();
				$attributes['google_uid'] = array($results['id']); 
				$attributes['google_name'] = array($results['name']);
				$attributes['google_email'] = array($results['email']);
				$attributes['google_given_name'] = array($results['given_name']);
				$attributes['google_family_name'] = array($results['family_name']);
				$attributes['google_eppn'] = array($results['id'] . '@google.com'); 
				SimpleSAML_Logger::debug('GOOGLE Returned Attributes: '. implode(", ", array_keys($attributes)));
				$state['Attributes'] = $attributes;
				
			}
		
				
		}
		
}

