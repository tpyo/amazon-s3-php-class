#!/usr/local/bin/php
<?php

// AWS access info
define('awsAccessKey', '1T4TYJW3DFJY2YFRZDR2');
define('awsSecretKey', 'z90GKSgCCtfwXZnezci+fW7vzrCwUWbS2r39h/71');


error_reporting(E_ALL);
if (extension_loaded('fileinfo')) $_ENV['MAGIC'] = '/usr/share/file/magic';
if (!extension_loaded('curl') && !@dl('curl.so')) exit("ERROR: CURL extension not loaded\n");


include 'S3.php';

S3::setAuth(awsAccessKey, awsSecretKey);


var_dump(S3::putObjectFile('/home/don/s3-php5-curl_0.2.2.tar.gz', 's3.undesigned.org.za', 's3-php5-curl_0.2.2.tar.gz', S3::ACL_PUBLIC_READ));
exit;


var_dump($s3->getAccessControlPolicy('logs.undesigned.org.za', ''));
exit;


var_dump($s3->getBucketLoggingStatus('s3.undesigned.org.za'));
exit;


var_dump($s3->listBuckets(true));
exit;



//var_dump($s3->enableBucketLogging('s3.undesigned.org.za', 'logs.undesigned.org.za', 'undesigned.log', array()));


exit;

//var_dump($s3->getObject('logs.undesigned.org.za', 'undesigned.log2008-04-28-19-25-20-284983F6F3B7C5CF'));
var_dump($s3->getBucket('logs.undesigned.org.za'));

exit;

if (($policy = $s3->getAccessControlPolicy('logs.undesigned.org.za', '')) !== false) {
	var_dump($s3->setAccessControlPolicy('logs.undesigned.org.za', '', $policy));
}

exit;

var_dump($s3->setACL('tpyo', 'test.txt', array(
	array('type' => 'Can', 'id' => 'c0dca1592c09d4d0e5e581385c3722621752be0c5fac60905437fe5ee8e7a108', 'permission' => 'FULL_CONTROL')
)));

//var_dump($s3->getObjectInfo('logs.undesigned.org.za', ''));


# EOF