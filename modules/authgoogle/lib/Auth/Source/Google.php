<?php
/**
 * Authenticate using Google openid connect
 * 07/2014
 * @author Sylvain MEDARD
 * @version $Id$
 */
 
class sspmod_authgoogle_Auth_Source_Google extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'authgoogle:init';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'authgoogle:AuthId';
	
	const ISSUER = 'accounts.google.com';
	
	private $state;
	private $stateID;
	
	// Google Developper Console :
	// https://code.google.com/apis/console
	private $key;
	private $secret;
	
	// Redirect_uri
	private $linkback; 
	
	private function curl_file_get_contents($url)
	{
    		$ch = curl_init();
    		$timeout = 5; // set to zero for no timeout
    		curl_setopt($ch, CURLOPT_URL, $url);
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    		$file_contents = curl_exec($ch);
    		curl_close($ch);
    		return $file_contents;
	}


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
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
		
		$this->linkback = SimpleSAML_Module::getModuleURL('authgoogle') . '/linkback.php';
		
		// Google Discovery Document
		/*$dd = 'https://accounts.google.com/.well-known/openid-configuration';
		$xmlddresponse =  $this->curl_file_get_contents($dd);
		SimpleSAML_Logger::debug('Google Response: '.$xmlddresponse);*/
	}
	



	/**
	 * Log-in using Google OpenID Connect platform
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		/* We are going to need the authId in order to retrieve this authentication source later. */
		$state[self::AUTHID] = $this->authId;

		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);

		$this->state = $state;
		$this->stateID = $stateID;

		
		
		// Lists of Google scopes : https://developers.google.com/+/api/oauth#login-scopes
		// openid : This scope informs the authorization server that the client is making an OpenID Connect request, and requests access to the authenticated user’s ID.
		// profile : This is the basic login scope. It requests that your app be given access to the authenticated user's basic profile information.
		// email : This scope requests that your app be given access to the user's Google account email address.
		$scopes = 'openid profile email';

		// Authenticate the user
		// https://developers.google.com/accounts/docs/OAuth2Login
		// Lits of Google APIs scopes: https://developers.google.com/+/api/oauth#login-scopes
        $authorizeURL = 'https://accounts.google.com/o/oauth2/auth?'
                                . 'client_id=' . urlencode($this->key)
                                . '&redirect_uri=' . urlencode($this->linkback)
                                . '&scope=' . urlencode($scopes)
                                . '&response_type=code'
                                . '&access_type=online'
                                . '&state=' . urlencode($stateID)
                ;

		
		$session = SimpleSAML_Session::getInstance();
		$session->setData('string', 'authStateId', $stateID);
 
        SimpleSAML_Utilities::redirectTrustedURL($authorizeURL);

	}


	/**
	 * We got authorization code : we can get token
	 * With the token, we can get user's info
	 * 
	 * @param array &$state  Information about the current authentication.
	 */
	public function finalStep(&$state) {
		assert('is_array($state)');

		// Retrieve Access token & id token
		// Documentation at:  
		// https://developers.google.com/accounts/docs/OAuth2Login#exchangecode
		
		$auth_code = $state['authgoogle:code'];
		SimpleSAML_Logger::debug('Google authorization code : ' . $auth_code);
		$fields=array(
    				'code'=>  urlencode($auth_code),
    				'client_id'=>  urlencode($this->key),
    				'client_secret'=>  urlencode($this->secret),
    				'redirect_uri'=>  urlencode($this->linkback),
    				'grant_type'=>  urlencode('authorization_code'),
		);
		$post = '';
		foreach($fields as $key=>$value) { $post .= $key.'='.$value.'&'; }
		$post = rtrim($post,'&');

		$curl = curl_init();
		curl_setopt($curl,CURLOPT_URL,'https://accounts.google.com/o/oauth2/token');
		curl_setopt($curl,CURLOPT_POST,5);
		curl_setopt($curl,CURLOPT_POSTFIELDS,$post);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
		$result = curl_exec($curl);
		curl_close($curl);
		
		if (!isset($result)) throw new SimpleSAML_Error_AuthSource($this->authId, 'Google Error getting tokens.');
		
		$response =  json_decode($result,true);
		
		$accesstoken = $response['access_token'];
		if (!isset($accesstoken)) 	throw new SimpleSAML_Error_AuthSource($this->authId, 'Google Error : No access token.');
		SimpleSAML_Logger::debug('Google DEBUG : AccessToken: '.$accesstoken);
	
		
		$id_token = $response['id_token'];
		if (!isset($id_token)) throw new SimpleSAML_Error_AuthSource($this->authId, 'Google Error : No id_token');
		SimpleSAML_Logger::debug('Google DEBUG : id_Token: '.$id_token);
	
		
		// Decode ID_token
		// http://openid.net/specs/openid-connect-basic-1_0.html#IDToken
		$id_array = explode('.', $id_token);
		SimpleSAML_Logger::debug('Google DEBUG : id_array: '.$id_array[1]);
		$id_body = base64_decode($id_array[1]);
		SimpleSAML_Logger::debug('Google DEBUG : id_body: '.$id_body);
		$idb = json_decode($id_body,true);
		
		foreach($idb as $key => $value) 
		{
			SimpleSAML_Logger::debug('Google DEBUG : id_Token ' . $key .' : ' .$value);
		}
	
		// DEBUG only : compare id_token with Google token_endpoint
		// The tokeninfo endpoint is useful for debugging but for production purposes, we recommend that you perform the validation locally
		// https://developers.google.com/accounts/docs/OAuth2Login#validatinganidtoken
		
		/*SimpleSAML_Logger::debug('DEBUG : id_Token encoded: '.$id_token);
		$urlidtoken = 'https://www.googleapis.com/oauth2/v1/tokeninfo?id_token='.$id_token;
		$responseidtoken = $this->curl_file_get_contents($urlidtoken);
		
		if (!isset($responseidtoken)) {
			throw new SimpleSAML_Error_AuthSource($this->authId, 'Error getting id token from Google endpoint.');
		}
		SimpleSAML_Logger::debug('DEBUG :id_token decoded from google endpoint'. $responseidtoken);
		*/
		
		// Verify id_token
		// http://openid.net/specs/openid-connect-basic-1_0.html#IDToken
		//[...]

		// Retrieve user info
		// https://developers.google.com/+/api/latest/people/getOpenIdConnect
		if ($response['expires_in']< time()) {
			$url = ('https://www.googleapis.com/plus/v1/people/me/openIdConnect?access_token='.$accesstoken);
			$xmlresponse =  $this->curl_file_get_contents($url);
			SimpleSAML_Logger::debug('Google Response: '.$xmlresponse);
			
			if (!isset($xmlresponse)) {
				throw new SimpleSAML_Error_AuthSource($this->authId, 'Error getting user profile.');
			}
		}	
		
		// Getting user's attributes from Google response
		$userinfo = json_decode($xmlresponse, true);
		foreach($userinfo as $key => $value)
		{
			SimpleSAML_Logger::debug('Google '.$key.':'.$value);
		}
		$attributes = array();
		$attributes['google_uid'] = array($userinfo['sub']);
		$attributes['google_name'] = array($userinfo['name']);
		$attributes['google_email'] = array($userinfo['email']);
		$attributes['google_given_name'] = array($userinfo['given_name']);
		$attributes['google_family_name'] = array($userinfo['family_name']);
		$attributes['google_eppn'] = array($userinfo['sub'] . '@google.com');  
		$state['Attributes'] = $attributes;

	}

}

