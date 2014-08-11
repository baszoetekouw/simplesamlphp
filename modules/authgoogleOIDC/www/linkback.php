<?php

/**
 * Handle linkback() response from Google API .
 *
 * @author Sylvain MEDARD
 * 07/2014
 * @version $Id$
 */

$stateId = $_REQUEST['state'];
$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_authgoogleOIDC_Auth_Source_GoogleOIDC::STAGE_INIT);


if (array_key_exists('code', $_REQUEST)) {
	SimpleSAML_Logger::debug('GOOGLE authorization code => ' . $_REQUEST['code']);

	// Good
	$state['authgoogleOIDC:code'] = $_REQUEST['code'];

	if (array_key_exists('exp', $_REQUEST))
		$state['authgoogleOIDC:exp'] = $_REQUEST['exp'];

} else {
	// error = 'access_denied' 
	if ($_REQUEST['error'] === 'access_denied') {
		$e = new SimpleSAML_Error_UserAborted();
		SimpleSAML_Auth_State::throwException($state, $e);
	}

	// Authentification failed
	throw new Exception('Authentication failed: [' . $_REQUEST['error_code'] . '] ' . $_REQUEST['error']);
}


if (isset($state))
{
	/* Find authentication source. */
	assert('array_key_exists(sspmod_authgoogleOIDC_Auth_Source_GoogleOIDC::AUTHID, $state)');
	$sourceId = $state[sspmod_authgoogleOIDC_Auth_Source_GoogleOIDC::AUTHID];

	$source = SimpleSAML_Auth_Source::getById($sourceId);
	if ($source === NULL) {
		throw new Exception('Could not find authentication source with id ' . $sourceId);
}


$source->finalStep($state);			
SimpleSAML_Auth_Source::completeAuth($state);

}

