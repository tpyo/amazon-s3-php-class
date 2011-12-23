#!/usr/local/bin/php
<?php
/**
* $Id$
*
* S3 class usage
*/

if (!class_exists('S3')) require_once 'S3.php';

// AWS access info
if (!defined('awsAccessKey')) define('awsAccessKey', 'change-this');
if (!defined('awsSecretKey')) define('awsSecretKey', 'change-this');

$uploadFile = dirname(__FILE__).'/S3.php'; // File to upload, we'll use the S3 class since it exists
$bucketName = uniqid('s3test'); // Temporary bucket

// If you want to use PECL Fileinfo for MIME types:
//if (!extension_loaded('fileinfo') && @dl('fileinfo.so')) $_ENV['MAGIC'] = '/usr/share/file/magic';


// Check if our upload file exists
if (!file_exists($uploadFile) || !is_file($uploadFile))
	exit("\nERROR: No such file: $uploadFile\n\n");

// Check for CURL
if (!extension_loaded('curl') && !@dl(PHP_SHLIB_SUFFIX == 'so' ? 'curl.so' : 'php_curl.dll'))
	exit("\nERROR: CURL extension not loaded\n\n");

// Pointless without your keys!
if (awsAccessKey == 'change-this' || awsSecretKey == 'change-this')
	exit("\nERROR: AWS access information required\n\nPlease edit the following lines in this file:\n\n".
	"define('awsAccessKey', 'change-me');\ndefine('awsSecretKey', 'change-me');\n\n");

// Instantiate the class
$s3 = new S3(awsAccessKey, awsSecretKey);

// List your buckets:
echo "S3::listBuckets(): ".print_r($s3->listBuckets(), 1)."\n";


// Create a bucket with public read access
if ($s3->putBucket($bucketName, S3::ACL_PUBLIC_READ)) {
	echo "Created bucket {$bucketName}".PHP_EOL;

	// Put our file (also with public read access)
	if ($s3->putObjectFile($uploadFile, $bucketName, baseName($uploadFile), S3::ACL_PUBLIC_READ)) {
		echo "S3::putObjectFile(): File copied to {$bucketName}/".baseName($uploadFile).PHP_EOL;


		// Get the contents of our bucket
		$contents = $s3->getBucket($bucketName);
		echo "S3::getBucket(): Files in bucket {$bucketName}: ".print_r($contents, 1);


		// Get object info
		$info = $s3->getObjectInfo($bucketName, baseName($uploadFile));
		echo "S3::getObjectInfo(): Info for {$bucketName}/".baseName($uploadFile).': '.print_r($info, 1);


		// You can also fetch the object into memory
		// var_dump("S3::getObject() to memory", $s3->getObject($bucketName, baseName($uploadFile)));

		// Or save it into a file (write stream)
		// var_dump("S3::getObject() to savefile.txt", $s3->getObject($bucketName, baseName($uploadFile), 'savefile.txt'));

		// Or write it to a resource (write stream)
		// var_dump("S3::getObject() to resource", $s3->getObject($bucketName, baseName($uploadFile), fopen('savefile.txt', 'wb')));



		// Get the access control policy for a bucket:
		// $acp = $s3->getAccessControlPolicy($bucketName);
		// echo "S3::getAccessControlPolicy(): {$bucketName}: ".print_r($acp, 1);

		// Update an access control policy ($acp should be the same as the data returned by S3::getAccessControlPolicy())
		// $s3->setAccessControlPolicy($bucketName, '', $acp);
		// $acp = $s3->getAccessControlPolicy($bucketName);
		// echo "S3::getAccessControlPolicy(): {$bucketName}: ".print_r($acp, 1);


		// Enable logging for a bucket:
		// $s3->setBucketLogging($bucketName, 'logbucket', 'prefix');

		// if (($logging = $s3->getBucketLogging($bucketName)) !== false) {
		// 	echo "S3::getBucketLogging(): Logging for {$bucketName}: ".print_r($contents, 1);
		// } else {
		// 	echo "S3::getBucketLogging(): Logging for {$bucketName} not enabled\n";
		// }

		// Disable bucket logging:
		// var_dump($s3->disableBucketLogging($bucketName));


		// Delete our file
		if ($s3->deleteObject($bucketName, baseName($uploadFile))) {
			echo "S3::deleteObject(): Deleted file\n";

			// Delete the bucket we created (a bucket has to be empty to be deleted)
			if ($s3->deleteBucket($bucketName)) {
				echo "S3::deleteBucket(): Deleted bucket {$bucketName}\n";
			} else {
				echo "S3::deleteBucket(): Failed to delete bucket (it probably isn't empty)\n";
			}

		} else {
			echo "S3::deleteObject(): Failed to delete file\n";
		}
	} else {
		echo "S3::putObjectFile(): Failed to copy file\n";
	}
} else {
	echo "S3::putBucket(): Unable to create bucket (it may already exist and/or be owned by someone else)\n";
}
