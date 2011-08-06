<?php
/**
 * Base on "smf-ppsldapauth" form http://www.getacoder.com/projects/ldap%20mod%20smf_143099.html
 * Original License is not known
 * Feel free to change and modify this Code for you own purposes
 *
 * @author Lukas Zurschmiede <l.zurschmiede@delightsoftware.com>
 * @copyright (c) 2011 by Piratenpartei Schweiz - http://www.piratenpartei.ch/
 * @license GPLv3
 */
//	ppsldapauth_enable -- will prevent anything from being done if not set
//	ppsldapauth_serverurl -- 'ldap://yourldapserver';
//	ppsldapauth_searchdn -- 'OU=Your Users,DC=yourdomain,DC=yourtld';
//	ppsldapauth_searchKey -- for MSAD will be 'sAMAccountName';
//	ppsldapauth_emailuselogin -- set to indicate that ppsldapauth_emailsuffix should be used
//	ppsldapauth_emailsuffix -- added to the login username to create the users' email addresses
//	ppsldapauth_emailattr -- if not using ppsldapauth_emailsuffix, the attribute in ldap to be used for the email addresses
//	ppsldapauth_locationuseou -- use the top level ou as the users' locations
//	ppsldapauth_locationattr -- if not using ppsldapauth_locationuseou, the attribute in ldap to be used for the locations
//	ppsldapauth_updateonlogin -- set to indicate that the user's information should be updated on every login
//	ppsldapauth_fullnameattr -- the attribute in ldap to be used for the fullname (cn for MSAD); required
//	ppsldapauth_regresnames -- set to indicate that ldap auth should autoregister/update users with reserved name logins
//	ppsldapauth_authresnames -- set to indicate that ldap auth should authenticate users with reserved name logins
//	ppsldapauth_binddn -- dn to bind to the ldap-server - $user$ is replaced by the Loginname
//	ppsldapauth_binduser -- Username to bind to the Ldap-Server if no binddn is given
//	ppsldapauth_bindpassword -- password to bind to the server
//	ppsldapauth_passwdindb -- set to indicate that ldap passwords should be stored in the local database

function smf_ppsldap_auth($username, $password, $seconds) {
	global $db_prefix, $user_info, $modSettings, $txt, $sourcedir, $smcFunc;
	require_once($sourcedir . '/Subs-Members.php');

	// not enabled or a reserved name is used
	if (!isset($modSettings['ppsldapauth_enable']) || !$modSettings['ppsldapauth_enable']) {
		return false;
	}

	// verify user exists in forum user database
	$request = $smcFunc['db_query']('', '
		SELECT id_member,password_salt
		FROM {db_prefix}members
		WHERE member_name = {string:member_name}
		LIMIT 1',
		array(
			'member_name' => $username
		)
	);
	$exists = $smcFunc['db_num_rows']($request) > 0;

	if (!$exists && (!isset($modSettigs['ppsldapauth_authresnames']) || !$modSettings['ppsldapauth_authresnames']) && isReservedName($username)) {
		return false;
	}

	$attributes = array($modSettings['ppsldapauth_fullnameattr']);
	if (isset($modSettings['ppsldapauth_emailattr']) && !empty($modSettings['ppsldapauth_emailattr'])) {
		$attributes[] = $modSettings['ppsldapauth_emailattr'];
	}

	if (isset($modSettings['ppsldapauth_locationattr']) && !empty($modSettings['ppsldapauth_locationattr'])) {
		$attributes[] = $modSettings['ppsldapauth_locationattr'];
	}

	$sha_passwd = sha1(strtolower($username) . un_htmlspecialchars(stripslashes($password)));
	if ($lds = ldap_connect($modSettings['ppsldapauth_serverurl'])) {
		// Try to use LDAPv3 - which is needed by MSAD for example and should be used on others also for security-reason
		if (ldap_set_option($lds, LDAP_OPT_PROTOCOL_VERSION, 3)) {
			ldap_set_option($lds, LDAP_OPT_REFERRALS, false);
		} else {
			ldap_set_option($lds, LDAP_OPT_REFERRALS, true);
		}

		// Bind to the LDAP-Server by given binddn, bind with the given username/password or bind anonymously and rebind with a username if one is given
		$bound = false;
		if ( isset($modSettings['ppsldapauth_binddn']) && $modSettings['ppsldapauth_binddn'] ) {
			$bound = ldap_bind($lds, $modSettings['ppsldapauth_binddn'], $modSettings['ppsldapauth_bindpassword']);
		}

		// Anonymous bind
		if (!$bound) {
			$bound = ldap_bind($lds);
		}

		// Re-bind using bindusername DN
		if ($bound && ( isset($modSettings['ppsldapauth_bindusername']) && $modSettings['ppsldapauth_bindusername'] ) && !( isset($modSettings['ppsldapauth_binddn']) && $modSettings['ppsldapauth_binddn'] ) ) {
			$search = @ldap_search($lds, $modSettings['ppsldapauth_searchdn'], "({$modSettings['ppsldapauth_searchkey']}={$modSettings['ppsldapauth_bindusername']})", array('dn'));
			$bound = ( ldap_count_entries($lds, $search) != 1 );
			if ($bound) {
				$entries = ldap_get_entries($lds, $search);
				$bound = ( !@ldap_bind($lds, $entries[0]['dn'], $modSettings['ppsldapauth_bindpassword']) );
			}
		}

		$userDN = '';
		if ($bound) {
			$search = ldap_search($lds, $modSettings['ppsldapauth_searchdn'], "(|({$modSettings['ppsldapauth_searchkey']}=$username))");
			$entries = ldap_get_entries($lds, $search);
			if (count($entries)) {
				$userDN = $entries[0]['dn'];
			}
		}

		// The Password matches if we can bind with $username
		if (!empty($userDN) && ldap_bind($lds, $userDN, $password)) {
			// clear passwd if we're not going to store it in the db
			if (isset($modSettings['ppsldapauth_passwdindb']) && !$modSettings['ppsldapauth_passwdindb']) {
				$sha_password = "LDAPOnly";
			}

			// if this isn't set we won't authenticate a reserved name that isn't already registered
			if ((!isset($modSettings['ppsldapauth_regresnames']) || !$modSettings['ppsldapauth_regresnames']) && isReservedName($username) && !$exists) {
				ldap_close($lds);
				return false;
			}

			// Update or Insert only if it's allowed
			// IF  ( user in SMF && UpdateOnLogin )
			// OR ( user not in SMF && ( RegisterReservedNames || Username not reserved ) )
			if ( ($exists && (!empty($modSettings['ppsldapauth_updateonlogin']) && $modSettings['ppsldapauth_updateonlogin'])) ||
			     (!$exists && ( (!empty($modSettings['ppsldapauth_regresnames']) && $modSettings['ppsldapauth_regresnames']) || !isReservedName($username)) )
			) {
				// Get user's full name (and possibly email address & location) from the directory
				$entries = ldap_get_entries($lds, ldap_search($lds, $modSettings['ppsldapauth_searchdn'], "({$modSettings['ppsldapauth_searchkey']}=$username)", $attributes));

				// Parse the lowest level Organizational Unit as their location
				if (isset($modSettings['ppsldapauth_locationuseou']) && $modSettings['ppsldapauth_locationuseou'] && (substr_count(strtolower($entries[0]['dn']), 'ou=') > 0)) {
					// Parse the lowest level Organizational Unit as the location
					$i1 = stripos($entries[0]['dn'], 'OU=') + 3;
					$i2 = stripos($entries[0]['dn'], ',OU=', $i1);
					$location = substr($entries[0]['dn'], $i1, $i2 - $i1);

				} else if (!empty($modSettings['ppsldapauth_locationattr']) && is_array($entries[0][$modSettings['ppsldapauth_locationattr']]) && ($entries[0][$modSettings['ppsldapauth_locationattr']]['count'] >= 1)) {
					$location = $entries[0][$modSettings['ppsldapauth_locationattr']][0];
				} else {
					$location = '';
				}

				if (isset($modSettings['ppsldapauth_emailuselogin']) && $modSettings['ppsldapauth_emailuselogin']) {
					$mail = $_POST['user'] . (isset($modSettings['ppsldapauth_emailsuffix']) ? $modSettings['ppsldapauth_emailsuffix'] : '');

				} else if (!empty($modSettings['ppsldapauth_emailattr']) && ($entries[0][$modSettings['ppsldapauth_emailattr']]['count'] >= 1)) {
					$mail = $entries[0][$modSettings['ppsldapauth_emailattr']][0];

				} else {
					$mail = 'none@dom.tld';
				}

				// email checking courtesy of Subs-Members.php
				if (empty($mail) || preg_match('~^[0-9A-Za-z=_+\-/][0-9A-Za-z=_\'+\-/\.]*@[\w\-]+(\.[\w\-]+)*(\.[\w]{2,6})$~', stripslashes($mail)) === 0 || strlen(stripslashes($mail)) > 255) {
					log_error(sprintf($txt[500], $username));
					$mail = 'none@dom.tld'; // we will let this go, although SMF doesn't really like missing email addresses
				}

				// User actually exists, so only update ldap-changeable data
				if ($exists) {
					$row = $smcFunc['db_fetch_assoc']($request);
					updateMemberData($row['id_member'], array(
						'passwd' => $sha_passwd,
						'password_salt' => $row['password_salt'],
						'passwd_flood' => '',
						'location' => $smcFunc['htmlspecialchars']($location),
						'email_address' => $mail,
						//'real_name' => $smcFunc['htmlspecialchars']($entries[0][$modSettings['ppsldapauth_fullnameattr']][0])
					));

					$smcFunc['db_free_result']($request);
					ldap_close($lds);
					return true;
				}

				// User does not exist in SMF database - create it
				require_once($sourcedir . '/Subs-Members.php');
				$regOptions = array(
					'username' => $username,
					'email' => $mail,
					'password' => $sha_passwd,
					'password_check' => $sha_passwd,
					'posts' => 0,
					'check_reserved_name' => !isset($modSettings['ppsldapauth_regresnames']) || !$modSettings['ppsldapauth_regresnames'],
					'check_password_strength' => false,
					'check_email_ban' => false,
					'send_welcome_email' => false,
					'require' => 'nothing',
					'date_registered' => time(),
					'member_ip' => $user_info['ip'],
					'is_activated' => 1,
					'validation_code' => '',
					'personal_text' => addslashes($modSettings['default_personalText']),
					'member_group' => empty($_POST['group']) ? 0 : (int) $_POST['group'],
					'extra_register_vars' => array(
						'location' => $smcFunc['htmlspecialchars']($location),
						'real_name' => $smcFunc['htmlspecialchars']($entries[0][$modSettings['ppsldapauth_fullnameattr']][0])
					)
				);
				$memberID = registerMember($regOptions);
				updateStats('member');

				// If it's enabled, increase the registrations for today.
				trackStats(array('registers' => '+'));

			} else {
				// The User exists and the Setting indicates to store the Password in the DB
				if (!isset($modSettings['ppsldapauth_passwdindb']) || $modSettings['ppsldapauth_passwdindb']) {
					$row = $smcFunc['db_fetch_assoc']($request);
					updateMemberData($row['id_member'], array('passwd' => $sha_passwd, 'password_salt' => $row['password_salt'], 'passwd_flood' => ''));
				}
			}
			$smcFunc['db_free_result']($request);
			ldap_close($lds);
			return true;
		}
	}
	ldap_close($lds);

	// allow authentication fallthrough to other methods (local database hashes of various kinds, by default)
	return false;
}

// Allow admin to register a User from LDAP-Directory in SMF before the user has logged in the first time
function smf_ppsldap_register() {
	global $context, $txt, $scripturl, $modSettings, $helptxt, $sourcedir, $smcFunc;

	if (!empty($_POST['regSubmit'])) {
		checkSession();

		foreach ($_POST as $key => $value) {
			if (!is_array($_POST[$key])) {
				$_POST[$key] = htmltrim__recursive(str_replace(array("\n", "\r"), '', $_POST[$key]));
			}
		}

		// Prepare to get data from ldap directory
		$attributes = array($modSettings['ppsldapauth_fullnameattr']);
		if (isset($modSettings['ppsldapauth_emailattr']) && !empty($modSettings['ppsldapauth_emailattr'])) {
			$attributes[] = $modSettings['ppsldapauth_emailattr'];
		}

		if (isset($modSettings['ppsldapauth_locationattr']) && !empty($modSettings['ppsldapauth_locationattr'])) {
			$attributes[] = $modSettings['ppsldapauth_locationattr'];
		}

		if ($lds = ldap_connect($modSettings['ppsldapauth_serverurl'])) {
			// Try to use LDAPv3 - which is needed by MSAD for example and should be used on others also for security-reason
			if (ldap_set_option($lds, LDAP_OPT_PROTOCOL_VERSION, 3)) {
				ldap_set_option($lds, LDAP_OPT_REFERRALS, false);
			} else {
				ldap_set_option($lds, LDAP_OPT_REFERRALS, true);
			}

			// Bind to the LDAP-Server by given binddn or bind anonymously and rebind with a username if one is given
			$bound = false;
			if (!empty($modSettings['ppsldapauth_binddn'])) {
				$bound = ldap_bind($lds, $modSettings['ppsldapauth_binddn'], $modSettings['ppsldapauth_bindpassword']);
			}

			// Anonymous bind
			if (!$bound) {
				$bound = ldap_bind($lds);
			}

			// Re-bind using bindusername DN
			if ($bound && ( isset($modSettings['ppsldapauth_bindusername']) && $modSettings['ppsldapauth_bindusername'] ) && !( isset($modSettings['ppsldapauth_binddn']) && $modSettings['ppsldapauth_binddn'] ) ) {
				$lsearch = ldap_search($lds, $modSettings['ppsldapauth_searchdn'], "({$modSettings['ppsldapauth_searchkey']}={$modSettings['ppsldapauth_bindusername']})", array('dn'));
				$bound = ( ldap_count_entries($lds, $lsearch) != 1 );
				if ($bound) {
					$entries = ldap_get_entries($lds, $lsearch);
					$bound = ( !@ldap_bind($lds, $entries[0]['dn'], $modSettings['ppsldapauth_bindpassword']) );
				}
			}

			if ($bound) {
				// Get full name (and possibly email address & location) from the directory
				$entries = ldap_get_entries($lds, ldap_search($lds, $modSettings['ppsldapauth_searchdn'], "({$modSettings['ppsldapauth_searchkey']}={$_POST['user']})", $attributes));

				// Parse the lowest level Organizational Unit as their location
				if (isset($modSettings['ppsldapauth_locationuseou']) && $modSettings['ppsldapauth_locationuseou'] && (substr_count(strtolower($entries[0]['dn']), 'ou=') > 0)) {
					// Parse the lowest level Organizational Unit as the location
					$i1 = stripos($entries[0]['dn'], 'OU=') + 3;
					$i2 = stripos($entries[0]['dn'], ',OU=', $i1);
					$location = substr($entries[0]['dn'], $i1, $i2 - $i1);

				} else if (!empty($modSettings['ppsldapauth_locationattr']) && is_array($entries[0][$modSettings['ppsldapauth_locationattr']]) && ($entries[0][$modSettings['ppsldapauth_locationattr']]['count'] >= 1)) {
					$location = $entries[0][$modSettings['ppsldapauth_locationattr']][0];
				} else {
					$location = '';
				}

				if (isset($modSettings['ppsldapauth_emailuselogin']) && $modSettings['ppsldapauth_emailuselogin']) {
					$mail = $_POST['user'] . (isset($modSettings['ppsldapauth_emailsuffix']) ? $modSettings['ppsldapauth_emailsuffix'] : '');

				} else if (!empty($modSettings['ppsldapauth_emailattr']) && ($entries[0][$modSettings['ppsldapauth_emailattr']]['count'] >= 1)) {
					$mail = $entries[0][$modSettings['ppsldapauth_emailattr']][0];

				} else {
					$mail = 'none@dom.tld';
				}

				// prevent this from being guessed prior to reset at first login
				$thepasswd = sha1(time() . mt_rand());

				$regOptions = array(
					'interface' => 'admin',
					'username' => $_POST['user'],
					'email' => $mail,
					'password' => $thepasswd, // replaced at login
					'password_check' => $thepasswd,
					'check_reserved_name' => !isset($modSettings['ppsldapauth_regresnames']) || !$modSettings['ppsldapauth_regresnames'],
					'check_password_strength' => false,
					'check_email_ban' => false,
					'send_welcome_email' => false,
					'require' => 'nothing',
					'member_group' => empty($_POST['group']) ? 0 : (int) $_POST['group'],
					'extra_register_vars' => array(
						'location' => '\'' . $smcFunc['htmlspecialchars']($location) . '\'',
						'real_name' => '\'' . $smcFunc['htmlspecialchars']($entries[0][$modSettings['ppsldapauth_fullnameattr']][0]) . '\''
					)
				);

				require_once($sourcedir . '/Subs-Members.php');
				$memberID = registerMember($regOptions);
				if (!empty($memberID)) {
					$context['new_member'] = array(
						'id' => $memberID,
						'name' => $_POST['user'],
						'href' => $scripturl . '?action=profile;u=' . $memberID,
						'link' => '<a href="' . $scripturl . '?action=profile;u=' . $memberID . '">' . $_POST['user'] . '</a>',
					);
					$context['registration_done'] = sprintf($txt['admin_register_done'], $context['new_member']['link']);
				}
			}
			ldap_close($lds);
		}
	}

	// Basic stuff.
	$context['sub_template'] = 'ppsldap_register';
	$context['page_title'] = $txt['registration_center'];

	// Load the assignable member groups.
	$request = $smcFunc['db_query']('','
		SELECT group_name, id_group
		FROM {db_prefix}membergroups
		WHERE id_group != {int:moderator_group}
			AND min_posts = {int:min_posts}' . (allowedTo('admin_forum') ? '' : '
			AND id_group != {int:admin_group}') . '
			AND hidden != {int:hidden_group}
		ORDER BY min_posts, CASE WHEN id_group < {int:newbie_group} THEN id_group ELSE {int:newbie_group} END, group_name',
		array(
			'moderator_group' => 3,
			'min_posts' => -1,
			'admin_group' => 1,
			'is_protected' => 1,
			'hidden_group' => 2,
			'newbie_group' => 4
		)
	);

	$context['member_groups'] = array(0 => $txt['admin_register_group_none']);
	while ($row = $smcFunc['db_fetch_assoc']($request)) {
		$context['member_groups'][$row['id_group']] = $row['group_name'];
	}
	$smcFunc['db_free_result']($request);
}


function template_ppsldap_register() {
	global $context, $settings, $options, $scripturl, $txt, $modSettings;

	echo '
		<div class="cat_bar">
			<h3 class="cat_bar">', $txt['ppsldapregister_title'], '</h3>
		</div>
		<form action="', $scripturl, '?action=admin;area=regcenter" method="post" accept-charset="', $context['character_set'], '" name="postForm" id="postForm">
			<span class="topslice"><span></span></span>
			<script language="JavaScript" type="text/javascript"><!-- // --><![]]><![CDATA[CDATA[
			// ]]]]><![CDATA[></script>
			<div class="content" id="register_screen">';

	if (!empty($context['registration_done'])) {
		echo '
				<div class="windowbg" id="profile_success">
					', $context['registration_done'], '
				</div>';
	}

	echo '
				<dl class="register_form" id="admin_register_form">
					<dt>
						<strong><label for="user_input">', $txt['admin_register_username'], ':</label></strong>
						<span class="smalltext" style="font-weight: normal;">', $txt['admin_register_username_desc'], '</span>
					</dt>
					<dd>
						<input type="text" name="user" id="user_input" tabindex="', $context['tabindex']++, '" size="30" maxlength="25" class="input_text" />
					</dd>';

	if (!empty($context['member_groups'])) {
		echo '
					<dt>
						<strong><label for="group_select">', $txt['admin_register_group'], ':</label></strong>
						<span class="smalltext">', $txt['admin_register_group_desc'], '</span>
					</dt>
					<dd>
						<select name="group" id="group_select" tabindex="', $context['tabindex']++, '">';

		foreach ($context['member_groups'] as $id => $name) {
			echo '
							<option value="', $id, '">', $name, '</option>';
		}
		echo '
						</select>
					</dd>';
	}

	echo '
				</dl>
				<div class="righttext">
					<input type="submit" name="regSubmit" value="', $txt['register'], '" tabindex="', $context['tabindex']++, '" class="button_submit" />
					<input type="hidden" name="sa" value="ppsldapregister" />
				</div>
			</div>
			<span class="botslice"><span></span></span>
			<input type="hidden" name="', $context['session_var'], '" value="', $context['session_id'], '" />
		</form>
	</div>
	<br class="clear" />';
}

?>
