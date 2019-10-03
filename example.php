#!/usr/local/bin/php
<?php
/**
* $Id$
*
* S3 class usage
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

// List your buckets:
echo "S3::listBuckets(): ".print_r(S3::listBuckets(), 1)."\n";


// Create a bucket with public read access
if (S3::putBucket($bucketName, S3::ACL_PUBLIC_READ)) {
	echo "Created bucket {$bucketName}".PHP_EOL;

	// Put our file (also with public read access)
	if (S3::putObjectFile($uploadFile, $bucketName, baseName($uploadFile), S3::ACL_PUBLIC_READ)) {
		echo "S3::putObjectFile(): File copied to {$bucketName}/".baseName($uploadFile).PHP_EOL;


		// Get the contents of our bucket
		$contents = S3::getBucket($bucketName);
		echo "S3::getBucket(): Files in bucket {$bucketName}: ".print_r($contents, 1);


		// Get object info
		$info = S3::getObjectInfo($bucketName, baseName($uploadFile));
		echo "S3::getObjectInfo(): Info for {$bucketName}/".baseName($uploadFile).': '.print_r($info, 1);


		// You can also fetch the object into memory
		// var_dump("S3::getObject() to memory", S3::getObject($bucketName, baseName($uploadFile)));

		// Or save it into a file (write stream)
		// var_dump("S3::getObject() to savefile.txt", S3::getObject($bucketName, baseName($uploadFile), 'savefile.txt'));

		// Or write it to a resource (write stream)
		// var_dump("S3::getObject() to resource", S3::getObject($bucketName, baseName($uploadFile), fopen('savefile.txt', 'wb')));



		// Get the access control policy for a bucket:
		// $acp = S3::getAccessControlPolicy($bucketName);
		// echo "S3::getAccessControlPolicy(): {$bucketName}: ".print_r($acp, 1);

		// Update an access control policy ($acp should be the same as the data returned by S3::getAccessControlPolicy())
		// S3::setAccessControlPolicy($bucketName, '', $acp);
		// $acp = S3::getAccessControlPolicy($bucketName);
		// echo "S3::getAccessControlPolicy(): {$bucketName}: ".print_r($acp, 1);


		// Enable logging for a bucket:
		// S3::setBucketLogging($bucketName, 'logbucket', 'prefix');

		// if (($logging = S3::getBucketLogging($bucketName)) !== false) {
		// 	echo "S3::getBucketLogging(): Logging for {$bucketName}: ".print_r($contents, 1);
		// } else {
		// 	echo "S3::getBucketLogging(): Logging for {$bucketName} not enabled\n";
		// }

		// Disable bucket logging:
		// var_dump(S3::disableBucketLogging($bucketName));


		// Delete our file
		if (S3::deleteObject($bucketName, baseName($uploadFile))) {
			echo "S3::deleteObject(): Deleted file\n";

			// Delete the bucket we created (a bucket has to be empty to be deleted)
			if (S3::deleteBucket($bucketName)) {
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
