<?php

use IPTools\IP;
use IPTools\Network;
use IPTools\Range;

/**
 * Example authentication source.
 *
 * This class is an example authentication source which will always return a user with
 * a static set of attributes.
 *
 * @author Bas Zoetekouw, SURFnet bv
 * @package SimpleSAMLphp
 */
class sspmod_exampleauth_Auth_Source_IPAddress extends SimpleSAML_Auth_Source {


	/**
	 * Array of (IPTools\Range,attributes) pairs
	 */
	private $ip_attributes = array();

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		// Call the parent constructor first, as required by the interface
		parent::__construct($info, $config);

		// Parse attributes
		// TODO: add overall attributes
		assert(array_key_exists($config,'ipranges') and is_array($config['ipranges']));

		foreach ($config['ipranges'] as $iprange => $attr)
		{
			try {
                $ip = Range::parse($iprange);
				$attr_norm = SimpleSAML\Utils\Attributes::normalizeAttributesArray($attr);
                $this->ip_attributes[] = array($iprange, $ip, $attr_norm);
			} catch(Exception $e) {
				throw new Exception("Invalid configuration for  '$iprange': " . $e->getMessage());
			}
		}

		# sort ip/attribute array by size of the ip range
		uasort($this->ip_attributes, function ($a,$b) { return count($a[1])<=>count($b[1]); } );

	}


	/**
	 * Log in using static attributes.
	 *
	 * @param array &$state Information about the current authentication.
	 * @throws SimpleSAML_Error_Error
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		$user_ip = new IP($_SERVER['REMOTE_ADDR']);
		SimpleSAML\Logger::info("User ip is ".$user_ip);

		foreach ($this->ip_attributes as $c)
		{
			list($iprange_txt,$iprange,$attr) = $c;
			SimpleSAML\Logger::info("Checking range $iprange_txt");
			if ($iprange->contains($user_ip))
			{
				SimpleSAML\Logger::info("Matched");
				$state['Attributes'] = $attr;
				return;
			}
		}
		throw new SimpleSAML_Error_Error('NOACCESS');
	}

}
