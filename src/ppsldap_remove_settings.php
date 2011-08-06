<?php
/*******************************************************************************
	ATTENTION: If you are trying to INSTALL this package, please access
	it directly, with a URL like the following:
	http://www.yourdomain.tld/forum/add_settings.php (or similar.)
================================================================================
	This script can be used to add new settings into the database for use
	with SMF's $modSettings array.  It is meant to be run either from the
	package manager or directly by URL.
*******************************************************************************/

// Set the below to true to overwrite already existing settings with the defaults. (not recommended.)
$overwrite_old_settings = true;

// List settings here in the format: setting_key => default_value.  Escape any "s. (" => \")
$mod_settings = array(
	'disableHashTime' => '0',
	'ldapauth_enable' => '0'
// intentionally leaving the other options here so that they will still be there if the mod
// is reinstalled, but making sure it will be disabled at reinstall in case there are setting
// changes that need to be addressed.
);

// If SSI.php is in the same place as this file, and SMF isn't defined, this is being run standalone.
if (file_exists(dirname(__FILE__) . '/SSI.php') && !defined('SMF'))
	require_once(dirname(__FILE__) . '/SSI.php');
// Hmm... no SSI.php and no SMF?
elseif (!defined('SMF'))
	die('<b>Error:</b> Cannot install - please verify you put this in the same place as SMF\'s index.php.');

// Turn the array defined above into a string of MySQL data.
$string = '';
foreach ($mod_settings as $k => $v)
	$string .= '
			(\'' . $k . '\', \'' . $v . '\'),';

// Sorted out the array defined above - now insert the data!
if ($string != '')
	$result = $smcFunc['db_query']('',"
		" . ($overwrite_old_settings ? 'REPLACE' : 'INSERT IGNORE') . " INTO {db_prefix}settings
			(variable, value)
		VALUES" . substr($string, 0, -1));

// Uh-oh spaghetti-oh!
if ($result === false)
	echo '<b>Error:</b> Database modifications failed!';

?>
