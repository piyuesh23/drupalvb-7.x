<?php
// $Id: drupalvb.inc.php,v 1.34 2009/03/09 04:46:21 sun Exp $

/**
 * @file
 * Drupal vB CRUD functions.
 */

/**
 * Set the necessary cookies for the user to be logged into the forum.
 *
 * Frontend cookie names:
 * - lastvisit, lastactivity, sessionhash
 * Backend cookie names:
 * - cpsession, userid, password
 *
 * However, in all cases the cookiedomain is NOT prefixed with a dot unless
 * cookie domain has not been manually altered to either a suggested value or
 * custom value in vB's settings.
 */
function drupalvb_set_login_cookies($userid) {
  // Load required vB user data.
  $result = drupalvb_db_query("SELECT userid, password, salt FROM {user} WHERE userid = %d", $userid);
  $vbuser = $result->fetchAssoc();
  if (!$vbuser) {
    return FALSE;
  }

  $vb_config = drupalvb_get('config');
  $vb_options = drupalvb_get('options');

  $cookie_prefix = (isset($vb_config['Misc']['cookieprefix']) ? $vb_config['Misc']['cookieprefix'] : 'bb');
  $cookie_path = $vb_options['cookiepath'];
  $now = REQUEST_TIME;
  $expire = $now + (@ini_get('session.cookie_lifetime') ? ini_get('session.cookie_lifetime') : 60 * 60 * 24 * 365);

  $vb_cookie_domain = (!empty($vb_options['cookiedomain']) ? $vb_options['cookiedomain'] : $GLOBALS['cookie_domain']);
  // Per RFC 2109, cookie domains must contain at least one dot other than the
  // first. For hosts such as 'localhost' or IP Addresses we don't set a cookie domain.
  // @see conf_init()
  if (!(count(explode('.', $vb_cookie_domain)) > 2 && !is_numeric(str_replace('.', '', $vb_cookie_domain)))) {
    $vb_cookie_domain = '';
  }

  // Clear out old session (if available).
  if (!empty($_COOKIE[$cookie_prefix . 'sessionhash'])) {
    drupalvb_db_query("DELETE FROM {session} WHERE sessionhash = '%s'", $_COOKIE[$cookie_prefix . 'sessionhash']);
  }
  // Setup user session.
  $ip = implode('.', array_slice(explode('.', drupalvb_get_ip()), 0, 4 - $vb_options['ipcheck']));
  $idhash = md5($_SERVER['HTTP_USER_AGENT'] . $ip);
  $sessionhash = md5($now . request_uri() . $idhash . $_SERVER['REMOTE_ADDR'] . user_password(6));

  drupalvb_db_query("REPLACE INTO {session} (sessionhash, userid, host, idhash, lastactivity, location, useragent, loggedin) VALUES ('%s', %d, '%s', '%s', %d, '%s', '%s', %d)", $sessionhash, $vbuser['userid'], substr($_SERVER['REMOTE_ADDR'], 0, 15), $idhash, $now, '/forum/', $_SERVER['HTTP_USER_AGENT'], 2);

  // Setup cookies.
  setcookie($cookie_prefix . 'sessionhash', $sessionhash, $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'lastvisit', $now, $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'lastactivity', $now, $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'userid', $vbuser['userid'], $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'password', md5($vbuser['password'] . variable_get('drupalvb_license', '')), $expire, $cookie_path, $vb_cookie_domain);
  return TRUE;
}


/**
 * Get vBulletin configuration options.
 */
function drupalvb_get_options() {
  static $options = array();
  if (empty($options)) {
    $result = drupalvb_db_query("SELECT varname,value from {setting}");

		$res = $result->fetchAllAssoc('varname');
    foreach($res as $var) {
      $options[$var->varname] = $var->value;
    }    
	}
  return $options;
}

/**
 * Get vBulletin configuration.
 */
function drupalvb_get_config() {
  static $config = array();

  // @todo Find & include vB's config automatically?
  // $files = file_scan_directory('.', '^config.php$', $nomask = array('.', '..', 'CVS', '.svn'));
  $config_file = drupal_get_path('module', 'drupalvb') . '/config.php';
  if (empty($config) && file_exists($config_file)) {
    require_once DRUPAL_ROOT . '/' . $config_file;
  }
  return $config;
}

/**
 * Create a user in vBulletin.
 *
 * @param object $account
 *   A Drupal user account.
 * @param array $edit
 *   Form values provided by hook_user().
 */
function drupalvb_create_user($account, $edit) {
  // Ensure we are not duplicating a user.
  
  $result = drupalvb_db_query("SELECT COUNT(userid) FROM {user} WHERE LOWER(username) = LOWER('%s')", drupalvb_htmlspecialchars($edit['name']))->fetchAssoc();
  if ($result['count(userid)'] > 0) {  
    return FALSE;
  }

  $salt = '';
  for ($i = 0; $i < 3; $i++) {
    $salt .= chr(rand(32, 126));
  }
  // Note: Password is already hashed during user export.
  if (isset($edit['md5pass'])) {
    $passhash = md5($edit['md5pass'] . $salt);
  }
  else {
    $passhash = md5(md5($edit['pass']) . $salt);
  }

  $passdate = date('Y-m-d', $account->created);
  $joindate = $account->created;

  // Attempt to grab the user title from the database.
  $result = drupalvb_db_query("SELECT title FROM {usertitle} WHERE minposts = 0");
  $resarray = $result->fetchAssoc();
  if ($resarray) {
    $usertitle = $resarray['title'];
  }
  else {
    $usertitle = 'Junior Member';
  }

  // Divide timezone by 3600, since vBulletin stores hours.
  $timezone = variable_get('date_default_timezone', 0);
  $timezone = ($timezone != 0 ? $timezone / 3600 : 0);

  // Default new user options: I got these by setting up a new user how I
  // wanted and looking in the database to see what options were set for him.
  $options = variable_get('drupalvb_default_options', '3415');

  // Default usergroup id.
  $usergroupid = variable_get('drupalvb_default_usergroup', '2');

  // Set up the insertion query.
  $result = drupalvb_db_query("INSERT INTO {user} (username, usergroupid, password, passworddate, usertitle, email, salt, showvbcode, languageid, timezoneoffset, posts, joindate, lastvisit, lastactivity, options, favcache, fav_games, arcade_mod_privs, arcade_sess_gid, arcade_sess_start, arcade_gtype, arcade_session) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', 1, %d, '%s', 0, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d')", drupalvb_htmlspecialchars($edit['name']), $usergroupid, $passhash, $passdate, $usertitle, $edit['mail'], $salt, drupalvb_get('languageid'), $timezone, $joindate, REQUEST_TIME, REQUEST_TIME, $options, '', '', '', 0, 0, 0, 0);

  $userid = drupalvb_db_last_insert_id('user', 'userid');

  drupalvb_db_query("INSERT INTO {userfield} (userid, field1, field2, field3, field4, temp) VALUES (%d, '%s', '%s', '%s', '%s', '%s')", $userid, '', '', '', '', '');
  drupalvb_db_query("INSERT INTO {usertextfield} (userid, subfolders, pmfolders, buddylist, ignorelist, signature, searchprefs) VALUES (%d, '%s', '%s', '%s', '%s', '%s', '%s')", $userid, '', '', '', '', '', '');

  // Insert new user into mapping table.
  drupalvb_set_mapping($account->uid, $userid);

  // Return userid of newly created account.
  return $userid;
}

/**
 * Update a user in vBulletin.
 */
function drupalvb_update_user($account, $edit) {
  $fields = $values = array();

  foreach ($edit as $field => $value) {
    if (empty($value)) {
      continue;
    }
    switch ($field) {
      case 'name':
        $fields[] = "username = '%s'";
        $values[] = drupalvb_htmlspecialchars($value);
        break;

      case 'pass':
        $fields[] = "password = '%s'";
        // Note: Password is already hashed during user export.
        if (isset($edit['md5pass'])) {
          $values[] = md5($edit['md5pass'] . $edit['salt']);
        }
        else {
          $values[] = md5(md5($value) . $edit['salt']);
        }
        $fields[] = "salt = '%s'";
        $values[] = $edit['salt'];
        $fields[] = "passworddate = '%s'";
        $values[] = date('Y-m-d', REQUEST_TIME);
        break;

      case 'mail':
        $fields[] = "email = '%s'";
        $values[] = $value;
        break;

      case 'language':
        $fields[] = "languageid = %d";
        $values[] = drupalvb_get('languageid', $value);
        break;
    }
  }
  $fields[] = 'lastactivity = %d';
  $values[] = REQUEST_TIME;

  // Use previous case insensitive username to update conflicting names.
  $values[] = drupalvb_htmlspecialchars($account->name);
  drupalvb_db_query("UPDATE {user} SET " . implode(', ', $fields) . " WHERE LOWER(username) = LOWER('%s')", $values);

  // Ensure this user exists in the mapping table.
  // When integrating an existing installation, the mapping may not yet exist.
  $userid = drupalvb_db_query("SELECT userid FROM {user} WHERE username = '%s'", drupalvb_htmlspecialchars($account->name))->fetchField();
}

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function drupalvb_htmlspecialchars($text) {
  $text = preg_replace('/&(?!#[0-9]+|shy;)/si', '&amp;', $text);
  return str_replace(array('<', '>', '"'), array('&lt;', '&gt;', '&quot;'), $text);
}

/**
 * Ensure that a mapping between two existing user accounts exists.
 *
 * @param $uid
 *   A Drupal user id.
 * @param $userid
 *   A vBulletin user id.
 */
function drupalvb_set_mapping($uid, $userid) {
  // TODO Please convert this statement to the D7 database API syntax.  
   $id = db_insert('drupalvb_users')
  	->fields(array(
    'uid' => $uid,
    'userid' => $userid,
  ))
  ->execute();  
}

/**
 * Determines the IP address of current user.
 */
function drupalvb_get_ip() {
  $ip = $_SERVER['REMOTE_ADDR'];

  if (isset($_SERVER['HTTP_CLIENT_IP'])) {
    $ip = $_SERVER['HTTP_CLIENT_IP'];
  }
  else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && preg_match_all('#\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#s', $_SERVER['HTTP_X_FORWARDED_FOR'], $matches)) {
    // Make sure we don't pick up an internal IP defined by RFC1918.
    foreach ($matches[0] as $match) {
      if (!preg_match("#^(10|172\.16|192\.168)\.#", $match)) {
        $ip = $match;
        break;
      }
    }
  }
  else if (isset($_SERVER['HTTP_FROM'])) {
    $ip = $_SERVER['HTTP_FROM'];
  }
  return $ip;
}

/**
 * Export all drupal users to vBulletin.
 */
function drupalvb_export_drupal_users() {
  module_load_include('inc', 'drupalvb');

  $result = db_query("SELECT * FROM {users} ORDER BY uid");
  $users = $result->fetchAllAssoc('name');
  foreach($users as $user) {
    if ($user->uid == 0) {
      continue;
    }

    // Let create/update functions know that passwords are hashed already.
    $user->md5pass = $user->pass;
    if (!drupalvb_create_user($user, (array) $user)) {
      // Username already exists, update email and password only.
      // Case insensitive username is required to detect collisions.
      $vbuser = drupalvb_db_query("SELECT salt FROM {user} WHERE LOWER(username) = LOWER('%s')", drupalvb_htmlspecialchars($user->name))->fetchAssoc();
      drupalvb_update_user($user, array_merge((array) $user, $vbuser));
    }
  }
}

/**
 * Clear all vB cookies for the current user.
 *
 * @see drupalvb_logout(), drupalvb_user_logout()
 */
function drupalvb_clear_cookies($userid = NULL) {
  $vb_config = drupalvb_get('config');
  $vb_options = drupalvb_get('options');

  $cookie_prefix = (isset($vb_config['Misc']['cookieprefix']) ? $vb_config['Misc']['cookieprefix'] : 'bb');
  $cookie_path = $vb_options['cookiepath'];
  $expire = REQUEST_TIME - 86400;

  $vb_cookie_domain = (!empty($vb_options['cookiedomain']) ? $vb_options['cookiedomain'] : $GLOBALS['cookie_domain']);
  // Per RFC 2109, cookie domains must contain at least one dot other than the
  // first. For hosts such as 'localhost' or IP Addresses we don't set a cookie domain.
  // @see conf_init()
  if (!(count(explode('.', $vb_cookie_domain)) > 2 && !is_numeric(str_replace('.', '', $vb_cookie_domain)))) {
    $vb_cookie_domain = '';
  }

  if (!empty($userid)) {
    drupalvb_db_query("DELETE FROM {session} WHERE userid = %d", $userid);
    drupalvb_db_query("UPDATE {user} SET lastvisit = %d WHERE userid = %d", REQUEST_TIME, $userid);
  }

  setcookie($cookie_prefix . 'sessionhash', '', $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'lastvisit', '', $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'lastactivity', '', $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'userid', '', $expire, $cookie_path, $vb_cookie_domain);
  setcookie($cookie_prefix . 'password', '', $expire, $cookie_path, $vb_cookie_domain);
}

/**
 * Get counts of new or recent posts for the current user.
 */
function drupalvb_get_recent_posts($scope = 'last') {
  global $user;

  // Queries the vB user database to find a matching set of user data.
  $result = drupalvb_db_query("SELECT userid, username, lastvisit FROM {user} WHERE username = '%s'", drupalvb_htmlspecialchars($user->name));

  // Make sure a user is logged in to get their last visit and appropriate post
  // count.
  if ($vb_user = $result->fetchAssoc()) {
    if ($scope == 'last') {
      $datecut = $vb_user['lastvisit'];
    }
    else if ($scope == 'daily') {
      $datecut = REQUEST_TIME - 86400;
    }
    $posts = drupalvb_db_query("SELECT COUNT(postid) FROM {post} WHERE dateline > %d", $datecut)->fetchAssoc();
  }
  else {
    $posts = 0;
  }
  return $posts;
}

/**
 * Get counts of guests and members currently online.
 */
function drupalvb_get_users_online() {
  $vb_options = drupalvb_get('options');

  $datecut          = REQUEST_TIME - $vb_options['cookietimeout'];
  $numbervisible    = 0;
  $numberregistered = 0;
  $numberguest      = 0;

  $result = drupalvb_db_query("SELECT user.username, user.usergroupid, session.userid, session.lastactivity FROM {session} AS session LEFT JOIN {user} AS user ON (user.userid = session.userid) WHERE session.lastactivity > %d", $datecut);

  $userinfos = array();
	$res = $result->fetchAllAssoc('userid',PDO::FETCH_ASSOC);
  foreach ($res as $loggedin) {
    $userid = $loggedin['userid'];
    if (!$userid) {
      $numberguest++;
    }
    else if (empty($userinfos[$userid]) || ($userinfos[$userid]['lastactivity'] < $loggedin['lastactivity'])) {
      $userinfos[$userid] = $loggedin;
    }
  }
  foreach ($userinfos as $userid => $loggedin) {
    $numberregistered++;
  }
  return array('guests' => $numberguest, 'members' => $numberregistered);
}

/**
 * Get vB language id by given ISO language code.
 */
function drupalvb_get_languageid($language = NULL) {
  static $vblanguages;

  if (!isset($vblanguages)) {
    $vblanguages = array();
    $result = drupalvb_db_query("SELECT languageid, title, languagecode FROM {language}");
    $res = $result->fetchAllAssoc('languageid',PDO::FETCH_ASSOC);    
    foreach($res as $lang) {
      $vblanguages[$lang['languagecode']] = $lang['languageid'];
    }
  }
  $options = drupalvb_get('options');
  return (!empty($language) && isset($vblanguages[$language]) ? $vblanguages[$language] : $vblanguages[$options['languageid']]);
}

/**
 * Get vB user roles.
 */
function drupalvb_get_roles() {
  $result = drupalvb_db_query("SELECT usergroupid, title FROM {usergroup}");

  $roles = array();
  $res = $result->fetchAllAssoc('usergroupid');
  foreach($res as $data) {
    $roles[$data->usergroupid] = $data->title;
  }
  if (!$roles) {
    $roles[] = t('No user roles could be found.');
  }
  return $roles;
}

