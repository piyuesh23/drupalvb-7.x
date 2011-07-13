<?php
// $Id: drupalvb_recent_posts_user.inc,v 1.2 2008/07/16 01:14:48 sun Exp $

/**
 * @file
 * Custom user profile block.
 */

/**
 * Callback function to supply a list of content types.
 */
function drupalvb_drupalvb_recent_posts_user_panels_content_types() {
  $items['drupalvb_recent_posts_user'] = array(
    'title' => t('Drupal vB: Recent forum posts by user'),
    'single' => TRUE,
    'content_types' => 'drupalvb_admin_content_types_drupalvb_recent_posts_user',
    'render callback' => 'drupalvb_content_drupalvb_recent_posts_user',
    'title callback' => 'drupalvb_admin_title_drupalvb_recent_posts_user',
  );
  return $items;
}

/**
 * Return all content types available.
 */
function drupalvb_admin_content_types_drupalvb_recent_posts_user() {
  return array(
    'block' => array(
      'title' => t('Recent forum posts by user'),
      'icon' => 'icon_user.png',
      'path' => panels_get_path('content_types/user'),
      'description' => t('Displays recent forum posts from a user.'),
      'required context' => new panels_required_context(t('User'), 'user'),
      'category' => t('User context'),
    ),
  );
}

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function drupalvb_content_drupalvb_recent_posts_user($conf, $panel_args, $context) {
  if (empty($context->data) || (!$context->data->access && !user_access('administer users'))) {
    return;
  }

  $block = new stdClass();
  $block->module = 'drupalvb';
  $block->subject = t('Recent forum posts by @name', array('@name' => $context->data->name));
  $block->content = drupalvb_block_recent_user($context->data);
  return $block;
}

/**
 * Returns the administrative title for a type.
 */
function drupalvb_admin_title_drupalvb_recent_posts_user($conf, $context) {
  return t('"@s" recent forum posts', array('@s' => $context->identifier));
}

