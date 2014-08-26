<?php


/**
 * Handle linkback() response from Battle.net API .
 *
 * @author Sylvain MEDARD
 * 07/2014
 * @package simpleSAMLphp
 * @version $Id$
 */

	$stateId = $_REQUEST['state'];
	$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_authbnet_Auth_Source_bnet::STAGE_INIT);

	if (array_key_exists('code', $_REQUEST)) {

		SimpleSAML_Logger::debug('bnet authorization code => ' . $_REQUEST['code']);

		// Good
		$state['authbnet:code'] = $_REQUEST['code'];

		if (array_key_exists('exp', $_REQUEST))
			$state['authbnet:exp'] = $_REQUEST['exp'];

	} else {
		if ($_REQUEST['error'] === 'access_denied') {
			$e = new SimpleSAML_Error_UserAborted();
			SimpleSAML_Auth_State::throwException($state, $e);
		}

		// Error
		throw new Exception('Authentication failed: [' . $_REQUEST['error_code'] . '] ' . $_REQUEST['error']);
	}


	if (isset($state))
	{
	/* Find authentication source. */
	assert('array_key_exists(sspmod_authbnet_Auth_Source_bnet::AUTHID, $state)');
	$sourceId = $state[sspmod_authbnet_Auth_Source_bnet::AUTHID];

	$source = SimpleSAML_Auth_Source::getById($sourceId);
	if ($source === NULL) {
		throw new Exception('Could not find authentication source with id ' . $sourceId);
	}


	$source->finalStep($state);			
	SimpleSAML_Auth_Source::completeAuth($state);

	}

