#!/usr/local/bin/php
<?php
/**
* $Id$
*
* Note: Although this wrapper works, it would be more efficient to use the S3 class instead
*/

if(file_exists('vendor/autoload.php'))
{
	require_once 'vendor/autoload.php';
}

if (!class_exists('S3'))
{
	require_once 'S3.php';
}

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
S3::registerStreamWrapper();

$bucketName = uniqid('s3test');

echo "Creating bucket: {$bucketName}\n";
var_dump(mkdir("s3://{$bucketName}"));

echo "\nWriting file: {$bucketName}/test.txt\n";
var_dump(file_put_contents("s3://{$bucketName}/test.txt", "Eureka!"));

echo "\nReading file: {$bucketName}/test.txt\n";
var_dump(file_get_contents("s3://{$bucketName}/test.txt"));

echo "\nContents for bucket: {$bucketName}\n";
foreach (new DirectoryIterator("s3://{$bucketName}") as $b) {
	echo "\t".$b."\n";
}

echo "\nUnlinking: {$bucketName}/test.txt\n";
var_dump(unlink("s3://{$bucketName}/test.txt"));

echo "\nRemoving bucket: {$bucketName}\n";
var_dump(rmdir("s3://{$bucketName}"));


#EOF