<?php
// $Id: drupalvb.admin-pages.inc,v 1.14 2011/01/09 03:56:31 sun Exp $

/**
 * @file
 * Drupal vB system settings.
 *
 * Most parts forked from Migrator module, http://drupal.org/project/migrator
 */

/**
 * Form builder function for DrupalvB integration settings.
 *
 * @todo Add vBulletin license.
 * @todo Add required vBulletin configuration values; remove drupalvb_get_config().
 */
function drupalvb_settings_integration() {

  if (!drupalvb_db_is_valid()) {
    drupal_goto('admin/config/drupalvb/database');
  }

  $form = array();

  $form['drupalvb_license'] = array(
    '#type' => 'textfield',
    '#title' => t('vBulletin license number'),
    '#default_value' => variable_get('drupalvb_license', ''),
    '#size' => 20,
    '#description' => t('Enter your vBulletin license number, which can be found at the top of any PHP file of vBulletin. This is required to generate proper session id hashes for cookies. Please note that this is not your customer number.'),
  );

  $form['drupalvb_dual_login'] = array(
    '#type' => 'checkbox',
    '#title' => t('Users login to vBulletin forum when they log into Drupal.'),
    '#default_value' => variable_get('drupalvb_dual_login', TRUE),
    '#description' => t('Select to enable the dual login feature.'),
  );

  $form['drupalvb_acct_generation'] = array(
    '#type' => 'checkbox',
    '#title' => t('Create matching vBulletin accounts for new Drupal users.'),
    '#default_value' => variable_get('drupalvb_acct_generation', TRUE),
    '#description' => t('Select to enable the matching account generation feature.'),
  );

  $form['drupalvb_acct_sync'] = array(
    '#type' => 'checkbox',
    '#title' => t('Synchronize Drupal account updates and deletions with vBulletin.'),
    '#default_value' => variable_get('drupalvb_acct_sync', TRUE),
    '#description' => t('Select to enable the account synchronization feature.'),
  );

  $roles = user_roles(FALSE,NULL);
  $form['drupalvb_default_usergroup'] = array(
    '#type' => 'select',
    '#title' => t('Usergroup for new users'),
    '#default_value' => variable_get('drupalvb_default_usergroup', 2),
    '#options' => $roles,
    '#description' => t('Select the default usergroup for created users.'),
  );

  $form['drupalvb_default_options'] = array(
    '#type' => 'textfield',
    '#title' => t('New User Options'),
    '#default_value' => variable_get('drupalvb_default_options', '3415'),
    '#size' => 20,
    '#maxlength' => 25,
    '#description' => t('The default options set to new users who register through Drupal.'),
  );


  return system_settings_form($form);
}

/**
 * Settings form for remote system database connection.
 */
function drupalvb_settings_database() {	
	global $databases;
	$db = array();
	$db_var = $databases['default']['default'];
  $form = array();
  $db = parse_url(variable_get('drupalvb_db', is_array($GLOBALS['db_url']) ? $GLOBALS['db_url']['default'] : $GLOBALS['db_url']));
  $form['db'] = array(
    '#type' => 'fieldset',
    '#title' => t('Database connection'),
  );
  $form['db']['scheme'] = array(
    '#type' => 'radios',
    '#title' => t('Database interface'),
    '#options' => array(
      'mysql' => 'MySQL',
      'mysqli' => 'MySQLi',
    ),
    '#default_value' => $db_var['driver'], // was: $db['scheme'],
    '#disabled' => TRUE,
    '#description' => t('Due to the database abstraction design in Drupal 5 and 6, only the current default database interface is supported.'),
  );
  $form['db']['host'] = array(
    '#type' => 'textfield',
    '#title' => t('Host'),
    '#default_value' => !empty($db['host']) ? $db['host'] : 'localhost',
    '#required' => TRUE,
  );
  $form['db']['path'] = array(
    '#type' => 'textfield',
    '#title' => t('Database'),
    '#default_value' => substr($db['path'], 1),
    '#required' => TRUE,
  );
  $form['db']['user'] = array(
    '#type' => 'textfield',
    '#title' => t('Username'),
    '#default_value' => $db_var['username'],
    '#required' => TRUE,
  );
  $form['db']['pass'] = array(
    '#type' => 'textfield',
    '#title' => t('Password'),
    '#default_value' => $db_var['password'],    
    '#required' => TRUE,
  );
  $form['db']['db_prefix'] = array(
    '#type' => 'textfield',
    '#title' => t('Table prefix'),
    '#default_value' => variable_get('drupalvb_db_prefix', 'vb_'),
  );
  $form[] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );
  return $form;
}

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function drupalvb_settings_database_submit($form, &$form_state) {
  $initial_import = FALSE;
  // If there is no database configuration yet, we want to execute an initial
  // user import later.
  if (!variable_get('drupalvb_db', 0)) {
    $initial_import = TRUE;
  }

  $url = $form_state['values']['scheme'] . '://' . $form_state['values']['user'] . ':' . $form_state['values']['pass'] . '@' . $form_state['values']['host'] . '/' . $form_state['values']['path'];
  variable_set('drupalvb_db', $url);
  variable_set('drupalvb_db_is_default', (is_array($GLOBALS['db_url']) ? $GLOBALS['db_url']['default'] == $url : $GLOBALS['db_url'] == $url));
  variable_set('drupalvb_db_prefix', $form_state['values']['db_prefix']);

//  if ($initial_import) {
    // First time setup; initialize DrupalvB's user mapping.
    module_load_include('inc', 'drupalvb');
    _drupalvb_init_user_map();
 // }
}

/**
 * Form builder function for DrupalvB actions.
 */
function drupalvb_settings_actions() {
  $form = array();
  $form['action']['action'] = array(
    '#type' => 'value',
    '#title' => 'Action',
  );
  $form['action'][] = array(
    '#type' => 'radio',
    '#name' => 'action',
    '#return_value' => 'export',
    '#title' => t('Export Drupal users to vBulletin'),
    '#description' => t('<strong>Warning:</strong> This export relies on usernames.  If an identical username exists in Drupal and vBulletin, the user account in vBulletin will be overwritten with data from Drupal (specifically: email address and password).'),
  );
  $form['action'][] = array(
    '#type' => 'radio',
    '#name' => 'action',
    '#return_value' => 'import',
    '#title' => t('Import vBulletin users into Drupal'),
    '#description' => t('Note: Importing all vBulletin users at once is not possible, because vBulletin stores hashed passwords.  Instead, Drupal vB implements an external authentication provider to automatically register vBulletin users upon their first login in Drupal.  There is no way to automate this for all existing users.'),
    '#disabled' => TRUE,
  );
  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Start'),
  );
  return $form;
}

/**
 * Form submit callback for action form.
 */
function drupalvb_settings_actions_submit($form, &$form_state) {
  switch ($form_state['values']['action']) {
    case 'export':
      drupalvb_export_drupal_users();
      drupal_set_message(t('Drupal users have been exported to vBulletin.'));
      break;
  }
}

/**
 * Form builder function for DrupalvB variables (Devel).
 */
function drupalvb_settings_variables() {
  $form = array();
  $options = drupalvb_get('options');
  foreach ($options as $key => $value) {
    $form['variables'][$key]['name'] = array('#value' => check_plain($key));
    $form['variables'][$key]['value'] = array('#value' => check_plain($value));
  }  
  ksort($form['variables']);
  return $form;
}

/**
 * Theme vBulletin options similar to Drupal variables (Devel).
 */
function theme_drupalvb_settings_variables($variables) {
  $form = $variables['form'];
  $header = array(t('Name'), t('Value'));
  $rows = array();  
  $i = 0;
  foreach (element_children($form['variables']) as $key) {		
    $rows[$i] = array(
      $form['variables'][$key]['name']['#value'],
      $form['variables'][$key]['value']['#value']
    );
    $i++;
  }
  $output = theme('table', array('header' => $header, 'rows' => $rows));
  $output .= drupal_render_children($form);
  return $output;
}

