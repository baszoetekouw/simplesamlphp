<?php

/**
 * Authenticate using LiveID.
 *
 * @author Cristiano Valli, Consortium GARR.
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_authwindowslive_Auth_Source_LiveID extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'authwindowslive:init';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'authwindowslive:AuthId';

	private $key;
	private $secret;

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
			throw new Exception('LiveID authentication source is not properly configured: missing [key]');

		$this->key = $config['key'];

		if (!array_key_exists('secret', $config))
			throw new Exception('LiveID authentication source is not properly configured: missing [secret]');

		$this->secret = $config['secret'];
	}


	/**
	 * Log-in using LiveID platform
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		/* We are going to need the authId in order to retrieve this authentication source later. */
		$state[self::AUTHID] = $this->authId;
		SimpleSAML_Logger::debug('$$$$authwindowslive auth state  = ' . $state['SimpleSAML_Auth_Default.Return']);
		SimpleSAML_Logger::debug('$$$$authwindowslive auth state  = ' . $state['SimpleSAML_Auth_Default.id']);
		SimpleSAML_Logger::debug('$$$$authwindowslive auth state  = ' . $state['SimpleSAML_Auth_Default.ErrorURL']);
		SimpleSAML_Logger::debug('$$$$authwindowslive auth state  = ' . $state['LogoutCallback']);
		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);

		SimpleSAML_Logger::debug('authwindowslive auth state id = ' . $stateID);

		// Authenticate the user
		// Documentation at:  http://msdn.microsoft.com/en-us/library/live/hh243641
		// http://msdn.microsoft.com/en-us/library/live/hh243647.aspx

                $authorizeURL = 'https://login.live.com/oauth20_authorize.srf'
                                . '?client_id=' . $this->key
                                . '&scope=' . urlencode('wl.signin,wl.basic,wl.emails')
                                . '&response_type=code'
                                . '&redirect_uri=' . urlencode(SimpleSAML_Module::getModuleUrl('authwindowslive') . '/linkback.php?wrap_client_state='.urlencode($stateID))            
                                . '&wrap_client_state=' . urlencode($stateID)
                ;
	
	
		SimpleSAML_Logger::debug('LIVE state: '.$state);

                SimpleSAML_Utilities::redirect($authorizeURL);
	}



	public function finalStep(&$state) {
		assert('is_array($state)');
		$stateID = SimpleSAML_Auth_State::getStateId($state);

		SimpleSAML_Logger::debug("oauth wrap:  Using this verification code [" .
			$state['authwindowslive:wrap_verification_code'] . "]");

		// Retrieve Access Token
		// Documentation at:  http://msdn.microsoft.com/en-us/library/live/hh243641
		// http://msdn.microsoft.com/en-us/library/live/hh243647.aspx
		$auth_code = $state['authwindowslive:wrap_verification_code'];
		$redirect_uri = SimpleSAML_Module::getModuleUrl('authwindowslive') . '/linkback.php?wrap_client_state='.urlencode($stateID);
		$fields=array(
    				'code'=>  urlencode($auth_code),
    				'client_id'=>  urlencode($this->key),
    				'client_secret'=>  urlencode($this->secret),
    				'redirect_uri'=>  urlencode($redirect_uri),
    				'grant_type'=>  urlencode('authorization_code')
		);
		$post = '';
		foreach($fields as $key=>$value) { $post .= $key.'='.$value.'&'; }
		$post = rtrim($post,'&');

		$curl = curl_init();
		curl_setopt($curl,CURLOPT_URL,'https://login.live.com/oauth20_token.srf');
		curl_setopt($curl,CURLOPT_POST,5);
		curl_setopt($curl,CURLOPT_POSTFIELDS,$post);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
		$result = curl_exec($curl);
		curl_close($curl);

		$response =  json_decode($result);
		$accesstoken = $response->access_token;
		SimpleSAML_Logger::debug('LIVE AccessToken: '.$accesstoken);

		// $url = 'https://apis.live.net/v5.0/me/contacts?access_token='.$accesstoken.'';
		$url = 'https://apis.live.net/v5.0/me?access_token='.$accesstoken.'';
		$xmlresponse =  $this->curl_file_get_contents($url);
		SimpleSAML_Logger::debug('LIVE Response: '.$xmlresponse);

		$xml = json_decode($xmlresponse, true);
		foreach($xml as $key => $value)
		{
			SimpleSAML_Logger::debug('LIVE '.$key.':'.$value);
		}
		$attributes = array();
		$attributes['windowslive_uid'] = array($xml['id']);
		//$attributes['uid']=$attributes['windowslive_uid'];
		$attributes['windowslive_name'] = array($xml['name']);
		//$attributes['cn']=$attributes['windowslive_name'];
		$attributes['windowslive_first_name'] = array($xml['first_name']);
		//$attributes['givenName']=$attributes['windowslive_first_name'];
		$attributes['windowslive_last_name'] = array($xml['last_name']);
		//$attributes['sn']=$attributes['windowslive_last_name'];
		//$attributes['windowslive_link'] = array($xml['link']);
		$attributes['windowslive_email'] = array($xml['emails']['account']);
		//$attributes['mail']=$attributes['windowslive_email'];
		/*$attributes['windowslive_birth_month'] = array($xml['birth_month']);
		$attributes['windowslive_gender'] = array($xml['gender']);
		$attributes['windowslive_city'] = array($xml['addresses']['personal']['city']);
		$attributes['windowslive_state'] = array($xml['addresses']['personal']['state']);
		$attributes['windowslive_region'] = array($xml['addresses']['personal']['region']);
		$attributes['windowslive_locale'] = array($xml['locale']);*/
		//$attributes['language']=$attributes['windowslive_locale'];
		//$attributes['windowslive_updated_time'] = array($xml['updated_time']);
		$attributes['windowslive_user'] = array($xml['id'] . '@live.com');
		
		$state['Attributes'] = $attributes;

	}

}
