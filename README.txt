/* $Id: README.txt,v 1.18 2009/08/02 01:25:44 sun Exp $ */

-- SUMMARY --

DrupalvB integrates vBulletin forums with Drupal.  It allows

- new and existing vBulletin users to log in to Drupal
- existing Drupal users to log in to vBulletin (*)
- new Drupal users to log in to vBulletin
- single/shared sign-on when logging in via Drupal
- updating user data in vBulletin upon update in Drupal
- deleting users in vBulletin upon deletion in Drupal

Unlike vbDrupal (a fork of Drupal), DrupalvB turns Drupal's user-base into the
primary user-base (while still allowing existing or new vBulletin forum users
to logon with their user data in Drupal) and does not require patches to Drupal
core.

*) requires initial export


For a full description visit the project page:
  http://drupal.org/project/drupalvb
Bug reports, feature suggestions and latest developments:
  http://drupal.org/project/issues/drupalvb


-- REQUIREMENTS --

* vBulletin 3.6 or newer (latest confirmed working version was 3.8.x)


-- INSTALLATION --

* Install as usual, see http://drupal.org/node/70151 for further information.

* After installing vBulletin, copy config.php from your vBulletin includes/
  directory into DrupalvB's module folder.

  Please note that you have to update this copy of config.php whenever the
  original file is altered!


-- CONFIGURATION --

* Configure DrupalvB's settings in administer >> Site configuration >> DrupalvB.
  Please note that you *must* supply a database connection, even if it is
  identical to Drupal's.

* Enable DrupalvB's blocks in administer >> Site building >> Blocks.


-- IMPLEMENTATION --

Note: The following steps assume that you are using clean URLs in Drupal.  If
      you do not, all paths need to be prefixed with 'index.php?q='.  Of course,
      all paths also need to be prefixed with the proper base path of your site.

To properly login, logout, and synchronize users between vBulletin and Drupal,

* open vBulletin's includes/config.php file and

  - ensure that, when connecting via MySQLi, the 'charset' option is configured
    as following:

      $config['Mysqli']['charset'] = 'utf8';

  - append the following to disable password MD5-hashing via JavaScript:

      /**
       * DrupalvB: Disable MD5-hashing of passwords via JavaScript.
       */
      define('DISABLE_PASSWORD_CLEARING', TRUE);

* log in to vBulletin's AdminCP, go to

    Styles & Templates >> Replacement Variable Manager

  and add the following replacement variables for your template:

  - login.php?do=login           => /drupalvb/login

  - login.php?do=logout          => /drupalvb/logout?

    (The trailing question mark is required.)

  - login.php?do=lostpw          => /user/password

  - register.php                 => /user/register

  Optionally, if http://drupal.org/project/me is installed or a custom redirect
  has been implemented, you can also add (or similar):

  - profile.php?do=editpassword  => /user/me/edit


* If you want to run your forums on a subdomain, f.e. forums.example.com rather
  than example.com/forums, then you need to use a common cookie domain for both
  domains.

  WARNING: A wrongly defined cookie domain can lead to a completely broken user
           authentication, both in Drupal and vBulletin.  If the cookie domain
           is set to a wrong value, all users are immediately logged out, and
           can no longer login, including super administrators!

  In vBulletin, go to

    vBulletin Options >> Expand Setting Groups
    >> Cookies and HTTP Header Options >> Cookie Domain >> Edit Settings

  select your domain without the subdomain (i.e. example.com), and save.

  In Drupal's settings.php, find the section about cookie domain determination
  (around line 150), and un-comment the following line (replacing 'example.com'
  with your domain):

    $cookie_domain = 'example.com';



-- CONTACT --

Current maintainers:
* Daniel F. Kudwien (sun) - http://drupal.org/user/54136
* Stefan M. Kudwien (smk-ka) - http://drupal.org/user/48898

This project has been sponsored by:
* UNLEASHED MIND
  Specialized in consulting and planning of Drupal powered sites, UNLEASHED
  MIND offers installation, development, theming, customization, and hosting
  to get you started. Visit http://www.unleashedmind.com for more information.

