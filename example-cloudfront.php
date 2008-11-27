#!/usr/local/bin/php
<?php
/**
* $Id$
*
* S3 class - CloudFront usage
*/

if (!class_exists('S3')) require_once 'S3.php';

// AWS access info
if (!defined('awsAccessKey')) define('awsAccessKey', 'change-this');
if (!defined('awsSecretKey')) define('awsSecretKey', 'change-this');


// Check for CURL
if (!extension_loaded('curl') && !@dl(PHP_SHLIB_SUFFIX == 'so' ? 'curl.so' : 'php_curl.dll'))
	exit("\nERROR: CURL extension not loaded\n\n");

// Pointless without your keys!
if (awsAccessKey == 'change-this' || awsSecretKey == 'change-this')
	exit("\nERROR: AWS access information required\n\nPlease edit the following lines in this file:\n\n".
	"define('awsAccessKey', 'change-me');\ndefine('awsSecretKey', 'change-me');\n\n");


S3::setAuth(awsAccessKey, awsSecretKey);


function test_createDistribution($bucket, $cnames = array()) {
	if (($dist = S3::createDistribution($bucket, true, $cnames, 'New distribution created')) !== false) {
		echo "createDistribution($bucket): "; var_dump($dist);
	} else {
		echo "createDistribution($bucket): Failed to create distribution\n";
	}
}

function test_listDistributions() {
	if (($dists = S3::listDistributions()) !== false) {
		if (sizeof($dists) == 0) echo "listDistributions(): No distributions\n";
		foreach ($dists as $dist) {
			var_dump($dist);
		}
	} else {
		echo "listDistributions(): Failed to get distribution list\n";
	}
}

function test_updateDistribution($distributionId, $enabled = false, $cnames = array()) {
	// To enable/disable a distribution configuration:
	if (($dist = S3::getDistribution($distributionId)) !== false) {
		$dist['enabled'] = $enabled;
		$dist['comment'] = $enabled ? 'Enabled' : 'Disabled';
		if (!isset($dist['cnames'])) $dist['cnames'] = array();
		foreach ($cnames as $cname) $dist['cnames'][$cname] = $cname;

		echo "updateDistribution($distributionId): "; var_dump(S3::updateDistribution($dist));
	} else {
		echo "getDistribution($distributionId): Failed to get distribution information for update\n";
	}
}

function test_deleteDistribution($distributionId) {
	// To delete a distribution configuration you must first set enable=false with
	// the updateDistrubution() method and wait for status=Deployed:
	if (($dist = S3::getDistribution($distributionId)) !== false) {
		if ($dist['status'] == 'Deployed') {
			echo "deleteDistribution($distributionId): "; var_dump(S3::deleteDistribution($dist));
		} else {
			echo "deleteDistribution($distributionId): Distribution not ready for deletion (status is not 'Deployed')\n";
			var_dump($dist);
		}
	}
}


//test_createDistribution($bucketName, array('my-optional-cname-alias.com'));
//test_listDistributions();
// "E4S5USZY109S8" is the distribution ID:
//test_updateDistribution('E4S5USZY109S8', false);
//test_deleteDistribution('E4S5USZY109S8');
