<?php
//if uninstall not called from WordPress exit
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) )
        exit ();
    
    if (is_multisite()){
        delete_site_option('acceptto_ikey');
        delete_site_option('acceptto_skey');
        delete_site_option('acceptto_host');
        delete_site_option('acceptto_roles');
    }
    else {
        delete_option('acceptto_ikey');
        delete_option('acceptto_skey');
        delete_option('acceptto_host');
        delete_option('acceptto_roles');
    }

    $meta_type  = 'user';
    $user_id    = 0; // This will be ignored, since we are deleting for all users.
    $meta_key   = 'acceptto_email';
    $meta_value = ''; // Also ignored. The meta will be deleted regardless of value.
    $delete_all = true;

    delete_metadata( $meta_type, $user_id, $meta_key, $meta_value, $delete_all );
?>
