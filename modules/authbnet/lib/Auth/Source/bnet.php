<?php
/**
 * Authenticate using Battle.net API
 * 07/2014
 * @author Sylvain MEDARD
 * @version $Id$
 */
 
class sspmod_authbnet_Auth_Source_bnet extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'authbnet:init';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'authbnet:AuthId';
	
	private $state;
	private $stateID;
	
	/**
	 * Client ID & Client secret 
	 * from Bnet dev : https://dev.battle.net/ 
	 */ 
	private $key;
	private $secret;
	
	/** 
	 * Redirect_uri
	 */
	private $linkback; 
	
	/**
	 * Curl operations
	 * 
	 * @param $url       url of the operation
	 * @return           repsonse of the curl operation
	 */
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
			throw new Exception('Bnet authentication source is not properly configured: missing [key]');

		$this->key = $config['key'];

		if (!array_key_exists('secret', $config))
			throw new Exception('Bnet authentication source is not properly configured: missing [secret]');

		$this->secret = $config['secret'];
		
		$this->linkback = SimpleSAML_Module::getModuleURL('authbnet') . '/linkback.php';
		
	}
	



	/**
	 * Log-in using Bnet OAuth2.0 API
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

		// Without scopes you will get access to a users account ID and BattleTag.
		//$scopes = 'wow.profile sc2.profile';

		// Authenticate the user
		// https://dev.battle.net/docs/read/oauth
        $authorizeURL = 'https://eu.battle.net/oauth/authorize?'
                                . 'client_id=' . urlencode($this->key)
                                . '&redirect_uri=' . urlencode($this->linkback)
                                //. '&scope=' . urlencode($scopes)
                                . '&response_type=code'
                                . '&access_type=online'
                                . '&state=' . urlencode($stateID)
                ;

		
		$session = SimpleSAML_Session::getInstance();
		$session->setData('string', 'authStateId', $stateID);
 
        SimpleSAML_Utilities::redirectTrustedURL($authorizeURL);

	}


	/**
	 * We get the tokens with the authorization code then we can get user's info
	 * with the access token
	 * 
	 * @param array &$state  Information about the current authentication.
	 */
	public function finalStep(&$state) {
		assert('is_array($state)');
		
		$auth_code = $state['authbnet:code'];
		SimpleSAML_Logger::debug('bnet authorization code : ' . $auth_code);
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
		curl_setopt($curl,CURLOPT_URL,'https://eu.battle.net/oauth/token');
		curl_setopt($curl,CURLOPT_POST,5);
		curl_setopt($curl,CURLOPT_POSTFIELDS,$post);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
		$result = curl_exec($curl);
		curl_close($curl);
		
		if (!isset($result)) throw new SimpleSAML_Error_AuthSource($this->authId, 'Bnet OAuth 2.0 Error getting token.');
		
		$response =  json_decode($result,true);
		
		$accesstoken = $response['access_token'];
		if (!isset($accesstoken)) 	throw new SimpleSAML_Error_AuthSource($this->authId, 'Bnet OAuth 2.0 Error : No access token.');
		SimpleSAML_Logger::debug('Bnet OAuth 2.0  DEBUG : AccessToken: '.$accesstoken);
	

		if ($response['expires_in']< time()) {
			$url = ('https://eu.api.battle.net/account/user/id?access_token=' . $accesstoken);
			$xmlresponse =  $this->curl_file_get_contents($url);
			
			if (!isset($xmlresponse)) {
				throw new SimpleSAML_Error_AuthSource($this->authId, 'Error getting user profile.');
			}
		}	
		
		// Getting user's Battle.net ID from Bnet response
		$userinfo = json_decode($xmlresponse, true);
		/*foreach($userinfo as $key => $value)
		{
			SimpleSAML_Logger::debug('Bnet '.$key.':'.$value);
		}*/
		SimpleSAML_Logger::debug('Bnet userinfo : ' .  var_export($userinfo, true));
		$attributes = array();
		$attributes['bnet_uid'] = array($userinfo['id']);
		$attributes['bnet_eppn'] = array($userinfo['id'] . '@battelnet.com');  
		$state['Attributes'] = $attributes;

	}
	
}	
