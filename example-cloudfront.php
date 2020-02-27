#!/usr/local/bin/php
<?php
/**
* $Id$
*
* S3 class - CloudFront usage
*/

require_once 'vendor/autoload.php';

// File to upload, we'll use this file since it exists
list($uploadFile) = get_included_files();

$bucketName = uniqid('s3test', false); // Temporary bucket

// Initialise S3
S3::Init(
        new S3Credentials(_getenv('ACCESS_KEY'), _getenv('SECRET_KEY')),
        _getenv('REGION', 'us-west-1')
    );


function test_createDistribution($bucket, $cnames = array()) {
	if (($dist = S3::createDistribution($bucket, true, $cnames, 'New distribution created')) !== false) {
		echo "createDistribution($bucket): "; var_dump($dist);
	} else {
		echo "createDistribution($bucket): Failed to create distribution\n";
	}
}

function test_listDistributions() {
	if (($dists = S3::listDistributions()) !== false) {
		if (count($dists) === 0) echo "listDistributions(): No distributions\n";
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
		if ($dist['status'] === 'Deployed') {
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
