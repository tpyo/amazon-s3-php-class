<?php
/**
* $Id$
*
* Copyright (c) 2013, Donovan Schönknecht.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* - Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Amazon S3 is a trademark of Amazon.com, Inc. or its affiliates.
*/

/**
* Amazon S3 PHP class
*
* @link http://undesigned.org.za/2007/10/22/amazon-s3-php-class
* @version 0.5.1-dev
*/
class S3
{
	// ACL flags
	const ACL_PRIVATE = 'private';
	const ACL_PUBLIC_READ = 'public-read';
	const ACL_PUBLIC_READ_WRITE = 'public-read-write';
	const ACL_AUTHENTICATED_READ = 'authenticated-read';

	const STORAGE_CLASS_STANDARD = 'STANDARD';
	const STORAGE_CLASS_RRS = 'REDUCED_REDUNDANCY';

	const SSE_NONE = '';
	const SSE_AES256 = 'AES256';

	/**
	 * The AWS Access key
	 *
	 * @var string
	 * @access private
	 * @static
	 */
	private static $__accessKey = null;
	
	/**
	 * AWS Secret Key
	 *
	 * @var string
	 * @access private
	 * @static
	 */
	private static $__secretKey = null;
	
	/**
	 * SSL Client key
	 *
	 * @var string
	 * @access private
	 * @static
	 */
	private static $__sslKey = null;
	
	/**
	 * AWS URI
	 *
	 * @var string
	 * @acess public
	 * @static
	 */
	public static $endpoint = 's3.amazonaws.com';
	
	/**
	 * Proxy information
	 *
	 * @var null|array
	 * @access public
	 * @static
	 */
	public static $proxy = null;
	
	/**
	 * Connect using SSL?
	 *
	 * @var bool
	 * @access public
	 * @static
	 */
	public static $useSSL = false;
	
	/**
	 * Use SSL validation?
	 *
	 * @var bool
	 * @access public
	 * @static
	 */
	public static $useSSLValidation = true;
	
	/**
	 * Use PHP exceptions?
	 *
	 * @var bool
	 * @access public
	 * @static
	 */
	public static $useExceptions = false;

	/**
	 * Time offset applied to time()
	 * @access private
	 * @static
	 */
	private static $__timeOffset = 0;

	/**
	 * SSL client key
	 *
	 * @var bool
	 * @access public
	 * @static
	 */
	public static $sslKey = null;
	
	/**
	 * SSL client certfificate
	 *
	 * @var string
	 * @acess public
	 * @static
	 */
	public static $sslCert = null;
	
	/**
	 * SSL CA cert (only required if you are having problems with your system CA cert)
	 *
	 * @var string
	 * @access public
	 * @static
	 */
	public static $sslCACert = null;
	
	/**
	 * AWS Key Pair ID
	 *
	 * @var string
	 * @access private
	 * @static
	 */
	private static $__signingKeyPairId = null;
	
	/**
	 * Key resource, freeSigningKey() must be called to clear it from memory
	 *
	 * @var bool
	 * @access private
	 * @static 
	 */
	private static $__signingKeyResource = false;


	/**
	* Constructor - if you're not using the class statically
	*
	* @param string $accessKey Access key
	* @param string $secretKey Secret key
	* @param boolean $useSSL Enable SSL
	* @param string $endpoint Amazon URI
	* @return void
	*/
	public function __construct($accessKey = null, $secretKey = null, $useSSL = false, $endpoint = 's3.amazonaws.com')
	{
		if ($accessKey !== null && $secretKey !== null)
			self::setAuth($accessKey, $secretKey);
		self::$useSSL = $useSSL;
		self::$endpoint = $endpoint;
	}


	/**
	* Set the service endpoint
	*
	* @param string $host Hostname
	* @return void
	*/
	public function setEndpoint($host)
	{
		self::$endpoint = $host;
	}

	/**
	* Set AWS access key and secret key
	*
	* @param string $accessKey Access key
	* @param string $secretKey Secret key
	* @return void
	*/
	public static function setAuth($accessKey, $secretKey)
	{
		self::$__accessKey = $accessKey;
		self::$__secretKey = $secretKey;
	}


	/**
	* Check if AWS keys have been set
	*
	* @return boolean
	*/
	public static function hasAuth() {
		return (self::$__accessKey !== null && self::$__secretKey !== null);
	}


	/**
	* Set SSL on or off
	*
	* @param boolean $enabled SSL enabled
	* @param boolean $validate SSL certificate validation
	* @return void
	*/
	public static function setSSL($enabled, $validate = true)
	{
		self::$useSSL = $enabled;
		self::$useSSLValidation = $validate;
	}


	/**
	* Set SSL client certificates (experimental)
	*
	* @param string $sslCert SSL client certificate
	* @param string $sslKey SSL client key
	* @param string $sslCACert SSL CA cert (only required if you are having problems with your system CA cert)
	* @return void
	*/
	public static function setSSLAuth($sslCert = null, $sslKey = null, $sslCACert = null)
	{
		self::$sslCert = $sslCert;
		self::$sslKey = $sslKey;
		self::$sslCACert = $sslCACert;
	}


	/**
	* Set proxy information
	*
	* @param string $host Proxy hostname and port (localhost:1234)
	* @param string $user Proxy username
	* @param string $pass Proxy password
	* @param constant $type CURL proxy type
	* @return void
	*/
	public static function setProxy($host, $user = null, $pass = null, $type = CURLPROXY_SOCKS5)
	{
		self::$proxy = array('host' => $host, 'type' => $type, 'user' => $user, 'pass' => $pass);
	}


	/**
	* Set the error mode to exceptions
	*
	* @param boolean $enabled Enable exceptions
	* @return void
	*/
	public static function setExceptions($enabled = true)
	{
		self::$useExceptions = $enabled;
	}


	/**
	* Set AWS time correction offset (use carefully)
	*
	* This can be used when an inaccurate system time is generating
	* invalid request signatures.  It should only be used as a last
	* resort when the system time cannot be changed.
	*
	* @param string $offset Time offset (set to zero to use AWS server time)
	* @return void
	*/
	public static function setTimeCorrectionOffset($offset = 0)
	{
		if ($offset == 0)
		{
			$rest = new S3Request('HEAD');
			$rest = $rest->getResponse();
			$awstime = $rest->headers['date'];
			$systime = time();			
			$offset = $systime > $awstime ? -($systime - $awstime) : ($awstime - $systime);
		}
		self::$__timeOffset = $offset;
	}


	/**
	* Set signing key
	*
	* @param string $keyPairId AWS Key Pair ID
	* @param string $signingKey Private Key
	* @param boolean $isFile Load private key from file, set to false to load string
	* @return boolean
	*/
	public static function setSigningKey($keyPairId, $signingKey, $isFile = true)
	{
		self::$__signingKeyPairId = $keyPairId;
		if ((self::$__signingKeyResource = openssl_pkey_get_private($isFile ?
		file_get_contents($signingKey) : $signingKey)) !== false) return true;
		self::__triggerError('S3::setSigningKey(): Unable to open load private key: '.$signingKey, __FILE__, __LINE__);
		return false;
	}


	/**
	* Free signing key from memory, MUST be called if you are using setSigningKey()
	*
	* @return void
	*/
	public static function freeSigningKey()
	{
		if (self::$__signingKeyResource !== false)
			openssl_free_key(self::$__signingKeyResource);
	}


	/**
	* Internal error handler
	*
	* @internal Internal error handler
	* @param string $message Error message
	* @param string $file Filename
	* @param integer $line Line number
	* @param integer $code Error code
	* @return void
	*/
	private static function __triggerError($message, $file, $line, $code = 0)
	{
		if (self::$useExceptions)
			throw new S3Exception($message, $file, $line, $code);
		else
			trigger_error($message, E_USER_WARNING);
	}


	/**
	* Get a list of buckets
	*
	* @param boolean $detailed Returns detailed bucket list when true
	* @return array | false
	*/
	public static function listBuckets($detailed = false)
	{
		$rest = new S3Request('GET', '', '', self::$endpoint);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::listBuckets(): [%s] %s", $rest->error['code'],
			$rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		$results = array();
		if (!isset($rest->body->Buckets)) return $results;

		if ($detailed)
		{
			if (isset($rest->body->Owner, $rest->body->Owner->ID, $rest->body->Owner->DisplayName))
			$results['owner'] = array(
				'id' => (string)$rest->body->Owner->ID, 'name' => (string)$rest->body->Owner->DisplayName
			);
			$results['buckets'] = array();
			foreach ($rest->body->Buckets->Bucket as $b)
				$results['buckets'][] = array(
					'name' => (string)$b->Name, 'time' => strtotime((string)$b->CreationDate)
				);
		} else
			foreach ($rest->body->Buckets->Bucket as $b) $results[] = (string)$b->Name;

		return $results;
	}


	/**
	* Get contents for a bucket
	*
	* If maxKeys is null this method will loop through truncated result sets
	*
	* @param string $bucket Bucket name
	* @param string $prefix Prefix
	* @param string $marker Marker (last file listed)
	* @param string $maxKeys Max keys (maximum number of keys to return)
	* @param string $delimiter Delimiter
	* @param boolean $returnCommonPrefixes Set to true to return CommonPrefixes
	* @return array | false
	*/
	public static function getBucket($bucket, $prefix = null, $marker = null, $maxKeys = null, $delimiter = null, $returnCommonPrefixes = false)
	{
		$rest = new S3Request('GET', $bucket, '', self::$endpoint);
		if ($maxKeys == 0) $maxKeys = null;
		if ($prefix !== null && $prefix !== '') $rest->setParameter('prefix', $prefix);
		if ($marker !== null && $marker !== '') $rest->setParameter('marker', $marker);
		if ($maxKeys !== null && $maxKeys !== '') $rest->setParameter('max-keys', $maxKeys);
		if ($delimiter !== null && $delimiter !== '') $rest->setParameter('delimiter', $delimiter);
		$response = $rest->getResponse();
		if ($response->error === false && $response->code !== 200)
			$response->error = array('code' => $response->code, 'message' => 'Unexpected HTTP status');
		if ($response->error !== false)
		{
			self::__triggerError(sprintf("S3::getBucket(): [%s] %s",
			$response->error['code'], $response->error['message']), __FILE__, __LINE__);
			return false;
		}

		$results = array();

		$nextMarker = null;
		if (isset($response->body, $response->body->Contents))
		foreach ($response->body->Contents as $c)
		{
			$results[(string)$c->Key] = array(
				'name' => (string)$c->Key,
				'time' => strtotime((string)$c->LastModified),
				'size' => (int)$c->Size,
				'hash' => substr((string)$c->ETag, 1, -1)
			);
			$nextMarker = (string)$c->Key;
		}

		if ($returnCommonPrefixes && isset($response->body, $response->body->CommonPrefixes))
			foreach ($response->body->CommonPrefixes as $c)
				$results[(string)$c->Prefix] = array('prefix' => (string)$c->Prefix);

		if (isset($response->body, $response->body->IsTruncated) &&
		(string)$response->body->IsTruncated == 'false') return $results;

		if (isset($response->body, $response->body->NextMarker))
			$nextMarker = (string)$response->body->NextMarker;

		// Loop through truncated results if maxKeys isn't specified
		if ($maxKeys == null && $nextMarker !== null && (string)$response->body->IsTruncated == 'true')
		do
		{
			$rest = new S3Request('GET', $bucket, '', self::$endpoint);
			if ($prefix !== null && $prefix !== '') $rest->setParameter('prefix', $prefix);
			$rest->setParameter('marker', $nextMarker);
			if ($delimiter !== null && $delimiter !== '') $rest->setParameter('delimiter', $delimiter);

			if (($response = $rest->getResponse()) == false || $response->code !== 200) break;

			if (isset($response->body, $response->body->Contents))
			foreach ($response->body->Contents as $c)
			{
				$results[(string)$c->Key] = array(
					'name' => (string)$c->Key,
					'time' => strtotime((string)$c->LastModified),
					'size' => (int)$c->Size,
					'hash' => substr((string)$c->ETag, 1, -1)
				);
				$nextMarker = (string)$c->Key;
			}

			if ($returnCommonPrefixes && isset($response->body, $response->body->CommonPrefixes))
				foreach ($response->body->CommonPrefixes as $c)
					$results[(string)$c->Prefix] = array('prefix' => (string)$c->Prefix);

			if (isset($response->body, $response->body->NextMarker))
				$nextMarker = (string)$response->body->NextMarker;

		} while ($response !== false && (string)$response->body->IsTruncated == 'true');

		return $results;
	}


	/**
	* Put a bucket
	*
	* @param string $bucket Bucket name
	* @param constant $acl ACL flag
	* @param string $location Set as "EU" to create buckets hosted in Europe
	* @return boolean
	*/
	public static function putBucket($bucket, $acl = self::ACL_PRIVATE, $location = false)
	{
		$rest = new S3Request('PUT', $bucket, '', self::$endpoint);
		$rest->setAmzHeader('x-amz-acl', $acl);

		if ($location !== false)
		{
			$dom = new DOMDocument;
			$createBucketConfiguration = $dom->createElement('CreateBucketConfiguration');
			$locationConstraint = $dom->createElement('LocationConstraint', $location);
			$createBucketConfiguration->appendChild($locationConstraint);
			$dom->appendChild($createBucketConfiguration);
			$rest->data = $dom->saveXML();
			$rest->size = strlen($rest->data);
			$rest->setHeader('Content-Type', 'application/xml');
		}
		$rest = $rest->getResponse();

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::putBucket({$bucket}, {$acl}, {$location}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Delete an empty bucket
	*
	* @param string $bucket Bucket name
	* @return boolean
	*/
	public static function deleteBucket($bucket)
	{
		$rest = new S3Request('DELETE', $bucket, '', self::$endpoint);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 204)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::deleteBucket({$bucket}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Create input info array for putObject()
	*
	* @param string $file Input file
	* @param mixed $md5sum Use MD5 hash (supply a string if you want to use your own)
	* @return array | false
	*/
	public static function inputFile($file, $md5sum = true)
	{
		if (!file_exists($file) || !is_file($file) || !is_readable($file))
		{
			self::__triggerError('S3::inputFile(): Unable to open input file: '.$file, __FILE__, __LINE__);
			return false;
		}
		return array('file' => $file, 'size' => filesize($file), 'md5sum' => $md5sum !== false ?
		(is_string($md5sum) ? $md5sum : base64_encode(md5_file($file, true))) : '');
	}


	/**
	* Create input array info for putObject() with a resource
	*
	* @param string $resource Input resource to read from
	* @param integer $bufferSize Input byte size
	* @param string $md5sum MD5 hash to send (optional)
	* @return array | false
	*/
	public static function inputResource(&$resource, $bufferSize = false, $md5sum = '')
	{
		if (!is_resource($resource) || (int)$bufferSize < 0)
		{
			self::__triggerError('S3::inputResource(): Invalid resource or buffer size', __FILE__, __LINE__);
			return false;
		}

		// Try to figure out the bytesize
		if ($bufferSize === false)
		{
			if (fseek($resource, 0, SEEK_END) < 0 || ($bufferSize = ftell($resource)) === false)
			{
				self::__triggerError('S3::inputResource(): Unable to obtain resource size', __FILE__, __LINE__);
				return false;
			}
			fseek($resource, 0);
		}

		$input = array('size' => $bufferSize, 'md5sum' => $md5sum);
		$input['fp'] =& $resource;
		return $input;
	}


	/**
	* Put an object
	*
	* @param mixed $input Input data
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Array of x-amz-meta-* headers
	* @param array $requestHeaders Array of request headers or content type as a string
	* @param constant $storageClass Storage class constant
	* @param constant $serverSideEncryption Server-side encryption
	* @return boolean
	*/
	public static function putObject($input, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $requestHeaders = array(), $storageClass = self::STORAGE_CLASS_STANDARD, $serverSideEncryption = self::SSE_NONE)
	{
		if ($input === false) return false;
		$rest = new S3Request('PUT', $bucket, $uri, self::$endpoint);

		if (!is_array($input))
		{
			$input = array(
				'data' => $input, 
				'size' => strlen($input),
				'md5sum' => base64_encode(md5($input, true))
			);
			$mime = self::_getMIMETypeByFilename($uri);
			if ($mime)
			{
				$input['type'] = $mime;
			}
		}

		// Data
		if (isset($input['fp']))
			$rest->fp =& $input['fp'];
		elseif (isset($input['file']))
			$rest->fp = @fopen($input['file'], 'rb');
		elseif (isset($input['data']))
			$rest->data = $input['data'];

		// Content-Length (required)
		if (isset($input['size']) && $input['size'] >= 0)
			$rest->size = $input['size'];
		else {
			if (isset($input['file']))
				$rest->size = filesize($input['file']);
			elseif (isset($input['data']))
				$rest->size = strlen($input['data']);
		}

		// Custom request headers (Content-Type, Content-Disposition, Content-Encoding)
		if (is_array($requestHeaders))
			foreach ($requestHeaders as $h => $v) $rest->setHeader($h, $v);
		elseif (is_string($requestHeaders)) // Support for legacy contentType parameter
			$input['type'] = $requestHeaders;

		// Content-Type
		if (!isset($input['type']))
		{
			if (isset($requestHeaders['Content-Type']))
				$input['type'] =& $requestHeaders['Content-Type'];
			elseif (isset($input['file']))
				$input['type'] = self::__getMIMEType($input['file']);
			else
				$input['type'] = 'application/octet-stream';
		}

		if ($storageClass !== self::STORAGE_CLASS_STANDARD) // Storage class
			$rest->setAmzHeader('x-amz-storage-class', $storageClass);

		if ($serverSideEncryption !== self::SSE_NONE) // Server-side encryption
			$rest->setAmzHeader('x-amz-server-side-encryption', $serverSideEncryption);

		// We need to post with Content-Length and Content-Type, MD5 is optional
		if ($rest->size >= 0 && ($rest->fp !== false || $rest->data !== false))
		{
			$rest->setHeader('Content-Type', $input['type']);
			if (isset($input['md5sum'])) $rest->setHeader('Content-MD5', $input['md5sum']);

			$rest->setAmzHeader('x-amz-acl', $acl);
			foreach ($metaHeaders as $h => $v) $rest->setAmzHeader('x-amz-meta-'.$h, $v);
			$rest->getResponse();
		} else
			$rest->response->error = array('code' => 0, 'message' => 'Missing input parameters');

		if ($rest->response->error === false && $rest->response->code !== 200)
			$rest->response->error = array('code' => $rest->response->code, 'message' => 'Unexpected HTTP status');
		if ($rest->response->error !== false)
		{
			self::__triggerError(sprintf("S3::putObject(): [%s] %s",
			$rest->response->error['code'], $rest->response->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Put an object from a file (legacy function)
	*
	* @param string $file Input file path
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Array of x-amz-meta-* headers
	* @param string $contentType Content type
	* @return boolean
	*/
	public static function putObjectFile($file, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = null)
	{
		return self::putObject(self::inputFile($file), $bucket, $uri, $acl, $metaHeaders, $contentType);
	}


	/**
	* Put an object from a string (legacy function)
	*
	* @param string $string Input data
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Array of x-amz-meta-* headers
	* @param string $contentType Content type
	* @return boolean
	*/
	public static function putObjectString($string, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = 'text/plain')
	{
		return self::putObject($string, $bucket, $uri, $acl, $metaHeaders, $contentType);
	}


	/**
	* Get an object
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param mixed $saveTo Filename or resource to write to
	* @return mixed
	*/
	public static function getObject($bucket, $uri, $saveTo = false)
	{
		$rest = new S3Request('GET', $bucket, $uri, self::$endpoint);
		if ($saveTo !== false)
		{
			if (is_resource($saveTo))
				$rest->fp =& $saveTo;
			else
				if (($rest->fp = @fopen($saveTo, 'wb')) !== false)
					$rest->file = realpath($saveTo);
				else
					$rest->response->error = array('code' => 0, 'message' => 'Unable to open save file for writing: '.$saveTo);
		}
		if ($rest->response->error === false) $rest->getResponse();

		if ($rest->response->error === false && $rest->response->code !== 200)
			$rest->response->error = array('code' => $rest->response->code, 'message' => 'Unexpected HTTP status');
		if ($rest->response->error !== false)
		{
			self::__triggerError(sprintf("S3::getObject({$bucket}, {$uri}): [%s] %s",
			$rest->response->error['code'], $rest->response->error['message']), __FILE__, __LINE__);
			return false;
		}
		return $rest->response;
	}


	/**
	* Get object information
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param boolean $returnInfo Return response information
	* @return mixed | false
	*/
	public static function getObjectInfo($bucket, $uri, $returnInfo = true)
	{
		$rest = new S3Request('HEAD', $bucket, $uri, self::$endpoint);
		$rest = $rest->getResponse();
		if ($rest->error === false && ($rest->code !== 200 && $rest->code !== 404))
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getObjectInfo({$bucket}, {$uri}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return $rest->code == 200 ? $returnInfo ? $rest->headers : true : false;
	}


	/**
	* Copy an object
	*
	* @param string $srcBucket Source bucket name
	* @param string $srcUri Source object URI
	* @param string $bucket Destination bucket name
	* @param string $uri Destination object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Optional array of x-amz-meta-* headers
	* @param array $requestHeaders Optional array of request headers (content type, disposition, etc.)
	* @param constant $storageClass Storage class constant
	* @return mixed | false
	*/
	public static function copyObject($srcBucket, $srcUri, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $requestHeaders = array(), $storageClass = self::STORAGE_CLASS_STANDARD)
	{
		$rest = new S3Request('PUT', $bucket, $uri, self::$endpoint);
		$rest->setHeader('Content-Length', 0);
		foreach ($requestHeaders as $h => $v) $rest->setHeader($h, $v);
		foreach ($metaHeaders as $h => $v) $rest->setAmzHeader('x-amz-meta-'.$h, $v);
		if ($storageClass !== self::STORAGE_CLASS_STANDARD) // Storage class
			$rest->setAmzHeader('x-amz-storage-class', $storageClass);
		$rest->setAmzHeader('x-amz-acl', $acl);
		$rest->setAmzHeader('x-amz-copy-source', sprintf('/%s/%s', $srcBucket, rawurlencode($srcUri)));
		if (sizeof($requestHeaders) > 0 || sizeof($metaHeaders) > 0)
			$rest->setAmzHeader('x-amz-metadata-directive', 'REPLACE');

		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::copyObject({$srcBucket}, {$srcUri}, {$bucket}, {$uri}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return isset($rest->body->LastModified, $rest->body->ETag) ? array(
			'time' => strtotime((string)$rest->body->LastModified),
			'hash' => substr((string)$rest->body->ETag, 1, -1)
		) : false;
	}


	/**
	* Set up a bucket redirection
	*
	* @param string $bucket Bucket name
	* @param string $location Target host name
	* @return boolean
	*/
	public static function setBucketRedirect($bucket = NULL, $location = NULL)
	{
		$rest = new S3Request('PUT', $bucket, '', self::$endpoint);

		if( empty($bucket) || empty($location) ) {
			self::__triggerError("S3::setBucketRedirect({$bucket}, {$location}): Empty parameter.", __FILE__, __LINE__);
			return false;
		}

		$dom = new DOMDocument;
		$websiteConfiguration = $dom->createElement('WebsiteConfiguration');
		$redirectAllRequestsTo = $dom->createElement('RedirectAllRequestsTo');
		$hostName = $dom->createElement('HostName', $location);
		$redirectAllRequestsTo->appendChild($hostName);
		$websiteConfiguration->appendChild($redirectAllRequestsTo);
		$dom->appendChild($websiteConfiguration);
		$rest->setParameter('website', null);
		$rest->data = $dom->saveXML();
		$rest->size = strlen($rest->data);
		$rest->setHeader('Content-Type', 'application/xml');
		$rest = $rest->getResponse();

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::setBucketRedirect({$bucket}, {$location}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Set logging for a bucket
	*
	* @param string $bucket Bucket name
	* @param string $targetBucket Target bucket (where logs are stored)
	* @param string $targetPrefix Log prefix (e,g; domain.com-)
	* @return boolean
	*/
	public static function setBucketLogging($bucket, $targetBucket, $targetPrefix = null)
	{
		// The S3 log delivery group has to be added to the target bucket's ACP
		if ($targetBucket !== null && ($acp = self::getAccessControlPolicy($targetBucket, '')) !== false)
		{
			// Only add permissions to the target bucket when they do not exist
			$aclWriteSet = false;
			$aclReadSet = false;
			foreach ($acp['acl'] as $acl)
			if ($acl['type'] == 'Group' && $acl['uri'] == 'http://acs.amazonaws.com/groups/s3/LogDelivery')
			{
				if ($acl['permission'] == 'WRITE') $aclWriteSet = true;
				elseif ($acl['permission'] == 'READ_ACP') $aclReadSet = true;
			}
			if (!$aclWriteSet) $acp['acl'][] = array(
				'type' => 'Group', 'uri' => 'http://acs.amazonaws.com/groups/s3/LogDelivery', 'permission' => 'WRITE'
			);
			if (!$aclReadSet) $acp['acl'][] = array(
				'type' => 'Group', 'uri' => 'http://acs.amazonaws.com/groups/s3/LogDelivery', 'permission' => 'READ_ACP'
			);
			if (!$aclReadSet || !$aclWriteSet) self::setAccessControlPolicy($targetBucket, '', $acp);
		}

		$dom = new DOMDocument;
		$bucketLoggingStatus = $dom->createElement('BucketLoggingStatus');
		$bucketLoggingStatus->setAttribute('xmlns', 'http://s3.amazonaws.com/doc/2006-03-01/');
		if ($targetBucket !== null)
		{
			if ($targetPrefix == null) $targetPrefix = $bucket . '-';
			$loggingEnabled = $dom->createElement('LoggingEnabled');
			$loggingEnabled->appendChild($dom->createElement('TargetBucket', $targetBucket));
			$loggingEnabled->appendChild($dom->createElement('TargetPrefix', $targetPrefix));
			// TODO: Add TargetGrants?
			$bucketLoggingStatus->appendChild($loggingEnabled);
		}
		$dom->appendChild($bucketLoggingStatus);

		$rest = new S3Request('PUT', $bucket, '', self::$endpoint);
		$rest->setParameter('logging', null);
		$rest->data = $dom->saveXML();
		$rest->size = strlen($rest->data);
		$rest->setHeader('Content-Type', 'application/xml');
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::setBucketLogging({$bucket}, {$targetBucket}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Get logging status for a bucket
	*
	* This will return false if logging is not enabled.
	* Note: To enable logging, you also need to grant write access to the log group
	*
	* @param string $bucket Bucket name
	* @return array | false
	*/
	public static function getBucketLogging($bucket)
	{
		$rest = new S3Request('GET', $bucket, '', self::$endpoint);
		$rest->setParameter('logging', null);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getBucketLogging({$bucket}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		if (!isset($rest->body->LoggingEnabled)) return false; // No logging
		return array(
			'targetBucket' => (string)$rest->body->LoggingEnabled->TargetBucket,
			'targetPrefix' => (string)$rest->body->LoggingEnabled->TargetPrefix,
		);
	}


	/**
	* Disable bucket logging
	*
	* @param string $bucket Bucket name
	* @return boolean
	*/
	public static function disableBucketLogging($bucket)
	{
		return self::setBucketLogging($bucket, null);
	}


	/**
	* Get a bucket's location
	*
	* @param string $bucket Bucket name
	* @return string | false
	*/
	public static function getBucketLocation($bucket)
	{
		$rest = new S3Request('GET', $bucket, '', self::$endpoint);
		$rest->setParameter('location', null);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getBucketLocation({$bucket}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return (isset($rest->body[0]) && (string)$rest->body[0] !== '') ? (string)$rest->body[0] : 'US';
	}


	/**
	* Set object or bucket Access Control Policy
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param array $acp Access Control Policy Data (same as the data returned from getAccessControlPolicy)
	* @return boolean
	*/
	public static function setAccessControlPolicy($bucket, $uri = '', $acp = array())
	{
		$dom = new DOMDocument;
		$dom->formatOutput = true;
		$accessControlPolicy = $dom->createElement('AccessControlPolicy');
		$accessControlList = $dom->createElement('AccessControlList');

		// It seems the owner has to be passed along too
		$owner = $dom->createElement('Owner');
		$owner->appendChild($dom->createElement('ID', $acp['owner']['id']));
		$owner->appendChild($dom->createElement('DisplayName', $acp['owner']['name']));
		$accessControlPolicy->appendChild($owner);

		foreach ($acp['acl'] as $g)
		{
			$grant = $dom->createElement('Grant');
			$grantee = $dom->createElement('Grantee');
			$grantee->setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
			if (isset($g['id']))
			{ // CanonicalUser (DisplayName is omitted)
				$grantee->setAttribute('xsi:type', 'CanonicalUser');
				$grantee->appendChild($dom->createElement('ID', $g['id']));
			}
			elseif (isset($g['email']))
			{ // AmazonCustomerByEmail
				$grantee->setAttribute('xsi:type', 'AmazonCustomerByEmail');
				$grantee->appendChild($dom->createElement('EmailAddress', $g['email']));
			}
			elseif ($g['type'] == 'Group')
			{ // Group
				$grantee->setAttribute('xsi:type', 'Group');
				$grantee->appendChild($dom->createElement('URI', $g['uri']));
			}
			$grant->appendChild($grantee);
			$grant->appendChild($dom->createElement('Permission', $g['permission']));
			$accessControlList->appendChild($grant);
		}

		$accessControlPolicy->appendChild($accessControlList);
		$dom->appendChild($accessControlPolicy);

		$rest = new S3Request('PUT', $bucket, $uri, self::$endpoint);
		$rest->setParameter('acl', null);
		$rest->data = $dom->saveXML();
		$rest->size = strlen($rest->data);
		$rest->setHeader('Content-Type', 'application/xml');
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::setAccessControlPolicy({$bucket}, {$uri}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Get object or bucket Access Control Policy
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @return mixed | false
	*/
	public static function getAccessControlPolicy($bucket, $uri = '')
	{
		$rest = new S3Request('GET', $bucket, $uri, self::$endpoint);
		$rest->setParameter('acl', null);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getAccessControlPolicy({$bucket}, {$uri}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}

		$acp = array();
		if (isset($rest->body->Owner, $rest->body->Owner->ID, $rest->body->Owner->DisplayName))
			$acp['owner'] = array(
				'id' => (string)$rest->body->Owner->ID, 'name' => (string)$rest->body->Owner->DisplayName
			);

		if (isset($rest->body->AccessControlList))
		{
			$acp['acl'] = array();
			foreach ($rest->body->AccessControlList->Grant as $grant)
			{
				foreach ($grant->Grantee as $grantee)
				{
					if (isset($grantee->ID, $grantee->DisplayName)) // CanonicalUser
						$acp['acl'][] = array(
							'type' => 'CanonicalUser',
							'id' => (string)$grantee->ID,
							'name' => (string)$grantee->DisplayName,
							'permission' => (string)$grant->Permission
						);
					elseif (isset($grantee->EmailAddress)) // AmazonCustomerByEmail
						$acp['acl'][] = array(
							'type' => 'AmazonCustomerByEmail',
							'email' => (string)$grantee->EmailAddress,
							'permission' => (string)$grant->Permission
						);
					elseif (isset($grantee->URI)) // Group
						$acp['acl'][] = array(
							'type' => 'Group',
							'uri' => (string)$grantee->URI,
							'permission' => (string)$grant->Permission
						);
					else continue;
				}
			}
		}
		return $acp;
	}


	/**
	* Delete an object
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @return boolean
	*/
	public static function deleteObject($bucket, $uri)
	{
		$rest = new S3Request('DELETE', $bucket, $uri, self::$endpoint);
		$rest = $rest->getResponse();
		if ($rest->error === false && $rest->code !== 204)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::deleteObject(): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Get a query string authenticated URL
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param integer $lifetime Lifetime in seconds
	* @param boolean $hostBucket Use the bucket name as the hostname
	* @param boolean $https Use HTTPS ($hostBucket should be false for SSL verification)
	* @return string
	*/
	public static function getAuthenticatedURL($bucket, $uri, $lifetime, $hostBucket = false, $https = false)
	{
		$expires = self::__getTime() + $lifetime;
		$uri = str_replace(array('%2F', '%2B'), array('/', '+'), rawurlencode($uri));
		return sprintf(($https ? 'https' : 'http').'://%s/%s?AWSAccessKeyId=%s&Expires=%u&Signature=%s',
		// $hostBucket ? $bucket : $bucket.'.s3.amazonaws.com', $uri, self::$__accessKey, $expires,
		$hostBucket ? $bucket : self::$endpoint.'/'.$bucket, $uri, self::$__accessKey, $expires,
		urlencode(self::__getHash("GET\n\n\n{$expires}\n/{$bucket}/{$uri}")));
	}


	/**
	* Get a CloudFront signed policy URL
	*
	* @param array $policy Policy
	* @return string
	*/
	public static function getSignedPolicyURL($policy)
	{
		$data = json_encode($policy);
		$signature = '';
		if (!openssl_sign($data, $signature, self::$__signingKeyResource)) return false;

		$encoded = str_replace(array('+', '='), array('-', '_', '~'), base64_encode($data));
		$signature = str_replace(array('+', '='), array('-', '_', '~'), base64_encode($signature));

		$url = $policy['Statement'][0]['Resource'] . '?';
		foreach (array('Policy' => $encoded, 'Signature' => $signature, 'Key-Pair-Id' => self::$__signingKeyPairId) as $k => $v)
			$url .= $k.'='.str_replace('%2F', '/', rawurlencode($v)).'&';
		return substr($url, 0, -1);
	}


	/**
	* Get a CloudFront canned policy URL
	*
	* @param string $url URL to sign
	* @param integer $lifetime URL lifetime
	* @return string
	*/
	public static function getSignedCannedURL($url, $lifetime)
	{
		return self::getSignedPolicyURL(array(
			'Statement' => array(
				array('Resource' => $url, 'Condition' => array(
					'DateLessThan' => array('AWS:EpochTime' => self::__getTime() + $lifetime)
				))
			)
		));
	}


	/**
	* Get upload POST parameters for form uploads
	*
	* @param string $bucket Bucket name
	* @param string $uriPrefix Object URI prefix
	* @param constant $acl ACL constant
	* @param integer $lifetime Lifetime in seconds
	* @param integer $maxFileSize Maximum filesize in bytes (default 5MB)
	* @param string $successRedirect Redirect URL or 200 / 201 status code
	* @param array $amzHeaders Array of x-amz-meta-* headers
	* @param array $headers Array of request headers or content type as a string
	* @param boolean $flashVars Includes additional "Filename" variable posted by Flash
	* @return object
	*/
	public static function getHttpUploadPostParams($bucket, $uriPrefix = '', $acl = self::ACL_PRIVATE, $lifetime = 3600,
	$maxFileSize = 5242880, $successRedirect = "201", $amzHeaders = array(), $headers = array(), $flashVars = false)
	{
		// Create policy object
		$policy = new stdClass;
		$policy->expiration = gmdate('Y-m-d\TH:i:s\Z', (self::__getTime() + $lifetime));
		$policy->conditions = array();
		$obj = new stdClass; $obj->bucket = $bucket; array_push($policy->conditions, $obj);
		$obj = new stdClass; $obj->acl = $acl; array_push($policy->conditions, $obj);

		$obj = new stdClass; // 200 for non-redirect uploads
		if (is_numeric($successRedirect) && in_array((int)$successRedirect, array(200, 201)))
			$obj->success_action_status = (string)$successRedirect;
		else // URL
			$obj->success_action_redirect = $successRedirect;
		array_push($policy->conditions, $obj);

		if ($acl !== self::ACL_PUBLIC_READ)
			array_push($policy->conditions, array('eq', '$acl', $acl));

		array_push($policy->conditions, array('starts-with', '$key', $uriPrefix));
		if ($flashVars) array_push($policy->conditions, array('starts-with', '$Filename', ''));
		foreach (array_keys($headers) as $headerKey)
			array_push($policy->conditions, array('starts-with', '$'.$headerKey, ''));
		foreach ($amzHeaders as $headerKey => $headerVal)
		{
			$obj = new stdClass;
			$obj->{$headerKey} = (string)$headerVal;
			array_push($policy->conditions, $obj);
		}
		array_push($policy->conditions, array('content-length-range', 0, $maxFileSize));
		$policy = base64_encode(str_replace('\/', '/', json_encode($policy)));

		// Create parameters
		$params = new stdClass;
		$params->AWSAccessKeyId = self::$__accessKey;
		$params->key = $uriPrefix.'${filename}';
		$params->acl = $acl;
		$params->policy = $policy; unset($policy);
		$params->signature = self::__getHash($params->policy);
		if (is_numeric($successRedirect) && in_array((int)$successRedirect, array(200, 201)))
			$params->success_action_status = (string)$successRedirect;
		else
			$params->success_action_redirect = $successRedirect;
		foreach ($headers as $headerKey => $headerVal) $params->{$headerKey} = (string)$headerVal;
		foreach ($amzHeaders as $headerKey => $headerVal) $params->{$headerKey} = (string)$headerVal;
		return $params;
	}


	/**
	* Create a CloudFront distribution
	*
	* @param string $bucket Bucket name
	* @param boolean $enabled Enabled (true/false)
	* @param array $cnames Array containing CNAME aliases
	* @param string $comment Use the bucket name as the hostname
	* @param string $defaultRootObject Default root object
	* @param string $originAccessIdentity Origin access identity
	* @param array $trustedSigners Array of trusted signers
	* @return array | false
	*/
	public static function createDistribution($bucket, $enabled = true, $cnames = array(), $comment = null, $defaultRootObject = null, $originAccessIdentity = null, $trustedSigners = array())
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::createDistribution({$bucket}, ".(int)$enabled.", [], '$comment'): %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}
		$useSSL = self::$useSSL;

		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('POST', '', '2010-11-01/distribution', 'cloudfront.amazonaws.com');
		$rest->data = self::__getCloudFrontDistributionConfigXML(
			$bucket.'.s3.amazonaws.com',
			$enabled,
			(string)$comment,
			(string)microtime(true),
			$cnames,
			$defaultRootObject,
			$originAccessIdentity,
			$trustedSigners
		);

		$rest->size = strlen($rest->data);
		$rest->setHeader('Content-Type', 'application/xml');
		$rest = self::__getCloudFrontResponse($rest);

		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 201)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::createDistribution({$bucket}, ".(int)$enabled.", [], '$comment'): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		} elseif ($rest->body instanceof SimpleXMLElement)
			return self::__parseCloudFrontDistributionConfig($rest->body);
		return false;
	}


	/**
	* Get CloudFront distribution info
	*
	* @param string $distributionId Distribution ID from listDistributions()
	* @return array | false
	*/
	public static function getDistribution($distributionId)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::getDistribution($distributionId): %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}
		$useSSL = self::$useSSL;

		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('GET', '', '2010-11-01/distribution/'.$distributionId, 'cloudfront.amazonaws.com');
		$rest = self::__getCloudFrontResponse($rest);

		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getDistribution($distributionId): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		elseif ($rest->body instanceof SimpleXMLElement)
		{
			$dist = self::__parseCloudFrontDistributionConfig($rest->body);
			$dist['hash'] = $rest->headers['hash'];
			$dist['id'] = $distributionId;
			return $dist;
		}
		return false;
	}


	/**
	* Update a CloudFront distribution
	*
	* @param array $dist Distribution array info identical to output of getDistribution()
	* @return array | false
	*/
	public static function updateDistribution($dist)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::updateDistribution({$dist['id']}): %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$useSSL = self::$useSSL;

		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('PUT', '', '2010-11-01/distribution/'.$dist['id'].'/config', 'cloudfront.amazonaws.com');
		$rest->data = self::__getCloudFrontDistributionConfigXML(
			$dist['origin'],
			$dist['enabled'],
			$dist['comment'],
			$dist['callerReference'],
			$dist['cnames'],
			$dist['defaultRootObject'],
			$dist['originAccessIdentity'],
			$dist['trustedSigners']
		);

		$rest->size = strlen($rest->data);
		$rest->setHeader('If-Match', $dist['hash']);
		$rest = self::__getCloudFrontResponse($rest);

		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::updateDistribution({$dist['id']}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		} else {
			$dist = self::__parseCloudFrontDistributionConfig($rest->body);
			$dist['hash'] = $rest->headers['hash'];
			return $dist;
		}
		return false;
	}


	/**
	* Delete a CloudFront distribution
	*
	* @param array $dist Distribution array info identical to output of getDistribution()
	* @return boolean
	*/
	public static function deleteDistribution($dist)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::deleteDistribution({$dist['id']}): %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$useSSL = self::$useSSL;

		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('DELETE', '', '2008-06-30/distribution/'.$dist['id'], 'cloudfront.amazonaws.com');
		$rest->setHeader('If-Match', $dist['hash']);
		$rest = self::__getCloudFrontResponse($rest);

		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 204)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::deleteDistribution({$dist['id']}): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		return true;
	}


	/**
	* Get a list of CloudFront distributions
	*
	* @return array
	*/
	public static function listDistributions()
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::listDistributions(): [%s] %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$useSSL = self::$useSSL;
		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('GET', '', '2010-11-01/distribution', 'cloudfront.amazonaws.com');
		$rest = self::__getCloudFrontResponse($rest);
		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::listDistributions(): [%s] %s",
			$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}
		elseif ($rest->body instanceof SimpleXMLElement && isset($rest->body->DistributionSummary))
		{
			$list = array();
			if (isset($rest->body->Marker, $rest->body->MaxItems, $rest->body->IsTruncated))
			{
				//$info['marker'] = (string)$rest->body->Marker;
				//$info['maxItems'] = (int)$rest->body->MaxItems;
				//$info['isTruncated'] = (string)$rest->body->IsTruncated == 'true' ? true : false;
			}
			foreach ($rest->body->DistributionSummary as $summary)
				$list[(string)$summary->Id] = self::__parseCloudFrontDistributionConfig($summary);

			return $list;
		}
		return array();
	}

	/**
	* List CloudFront Origin Access Identities
	*
	* @return array
	*/
	public static function listOriginAccessIdentities()
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::listOriginAccessIdentities(): [%s] %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('GET', '', '2010-11-01/origin-access-identity/cloudfront', 'cloudfront.amazonaws.com');
		$rest = self::__getCloudFrontResponse($rest);
		$useSSL = self::$useSSL;

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			trigger_error(sprintf("S3::listOriginAccessIdentities(): [%s] %s",
			$rest->error['code'], $rest->error['message']), E_USER_WARNING);
			return false;
		}

		if (isset($rest->body->CloudFrontOriginAccessIdentitySummary))
		{
			$identities = array();
			foreach ($rest->body->CloudFrontOriginAccessIdentitySummary as $identity)
				if (isset($identity->S3CanonicalUserId))
					$identities[(string)$identity->Id] = array('id' => (string)$identity->Id, 's3CanonicalUserId' => (string)$identity->S3CanonicalUserId);
			return $identities;
		}
		return false;
	}


	/**
	* Invalidate objects in a CloudFront distribution
	*
	* Thanks to Martin Lindkvist for S3::invalidateDistribution()
	*
	* @param string $distributionId Distribution ID from listDistributions()
	* @param array $paths Array of object paths to invalidate
	* @return boolean
	*/
	public static function invalidateDistribution($distributionId, $paths)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::invalidateDistribution(): [%s] %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$useSSL = self::$useSSL;
		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('POST', '', '2010-08-01/distribution/'.$distributionId.'/invalidation', 'cloudfront.amazonaws.com');
		$rest->data = self::__getCloudFrontInvalidationBatchXML($paths, (string)microtime(true));
		$rest->size = strlen($rest->data);
		$rest = self::__getCloudFrontResponse($rest);
		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 201)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			trigger_error(sprintf("S3::invalidate('{$distributionId}',{$paths}): [%s] %s",
			$rest->error['code'], $rest->error['message']), E_USER_WARNING);
			return false;
		}
		return true;
	}


	/**
	* Get a InvalidationBatch DOMDocument
	*
	* @internal Used to create XML in invalidateDistribution()
	* @param array $paths Paths to objects to invalidateDistribution
	* @param int $callerReference
	* @return string
	*/
	private static function __getCloudFrontInvalidationBatchXML($paths, $callerReference = '0')
	{
		$dom = new DOMDocument('1.0', 'UTF-8');
		$dom->formatOutput = true;
		$invalidationBatch = $dom->createElement('InvalidationBatch');
		foreach ($paths as $path)
			$invalidationBatch->appendChild($dom->createElement('Path', $path));

		$invalidationBatch->appendChild($dom->createElement('CallerReference', $callerReference));
		$dom->appendChild($invalidationBatch);
		return $dom->saveXML();
	}


	/**
	* List your invalidation batches for invalidateDistribution() in a CloudFront distribution
	*
	* http://docs.amazonwebservices.com/AmazonCloudFront/latest/APIReference/ListInvalidation.html
	* returned array looks like this:
	*	Array
	*	(
	*		[I31TWB0CN9V6XD] => InProgress
	*		[IT3TFE31M0IHZ] => Completed
	*		[I12HK7MPO1UQDA] => Completed
	*		[I1IA7R6JKTC3L2] => Completed
	*	)
	*
	* @param string $distributionId Distribution ID from listDistributions()
	* @return array
	*/
	public static function getDistributionInvalidationList($distributionId)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::getDistributionInvalidationList(): [%s] %s",
			"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$useSSL = self::$useSSL;
		self::$useSSL = true; // CloudFront requires SSL
		$rest = new S3Request('GET', '', '2010-11-01/distribution/'.$distributionId.'/invalidation', 'cloudfront.amazonaws.com');
		$rest = self::__getCloudFrontResponse($rest);
		self::$useSSL = $useSSL;

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			trigger_error(sprintf("S3::getDistributionInvalidationList('{$distributionId}'): [%s]",
			$rest->error['code'], $rest->error['message']), E_USER_WARNING);
			return false;
		}
		elseif ($rest->body instanceof SimpleXMLElement && isset($rest->body->InvalidationSummary))
		{
			$list = array();
			foreach ($rest->body->InvalidationSummary as $summary)
				$list[(string)$summary->Id] = (string)$summary->Status;

			return $list;
		}
		return array();
	}


	/**
	* Get a DistributionConfig DOMDocument
	*
	* http://docs.amazonwebservices.com/AmazonCloudFront/latest/APIReference/index.html?PutConfig.html
	*
	* @internal Used to create XML in createDistribution() and updateDistribution()
	* @param string $bucket S3 Origin bucket
	* @param boolean $enabled Enabled (true/false)
	* @param string $comment Comment to append
	* @param string $callerReference Caller reference
	* @param array $cnames Array of CNAME aliases
	* @param string $defaultRootObject Default root object
	* @param string $originAccessIdentity Origin access identity
	* @param array $trustedSigners Array of trusted signers
	* @return string
	*/
	private static function __getCloudFrontDistributionConfigXML($bucket, $enabled, $comment, $callerReference = '0', $cnames = array(), $defaultRootObject = null, $originAccessIdentity = null, $trustedSigners = array())
	{
		$dom = new DOMDocument('1.0', 'UTF-8');
		$dom->formatOutput = true;
		$distributionConfig = $dom->createElement('DistributionConfig');
		$distributionConfig->setAttribute('xmlns', 'http://cloudfront.amazonaws.com/doc/2010-11-01/');

		$origin = $dom->createElement('S3Origin');
		$origin->appendChild($dom->createElement('DNSName', $bucket));
		if ($originAccessIdentity !== null) $origin->appendChild($dom->createElement('OriginAccessIdentity', $originAccessIdentity));
		$distributionConfig->appendChild($origin);

		if ($defaultRootObject !== null) $distributionConfig->appendChild($dom->createElement('DefaultRootObject', $defaultRootObject));

		$distributionConfig->appendChild($dom->createElement('CallerReference', $callerReference));
		foreach ($cnames as $cname)
			$distributionConfig->appendChild($dom->createElement('CNAME', $cname));
		if ($comment !== '') $distributionConfig->appendChild($dom->createElement('Comment', $comment));
		$distributionConfig->appendChild($dom->createElement('Enabled', $enabled ? 'true' : 'false'));

		$trusted = $dom->createElement('TrustedSigners');
		foreach ($trustedSigners as $id => $type)
			$trusted->appendChild($id !== '' ? $dom->createElement($type, $id) : $dom->createElement($type));
		$distributionConfig->appendChild($trusted);

		$dom->appendChild($distributionConfig);
		//var_dump($dom->saveXML());
		return $dom->saveXML();
	}


	/**
	* Parse a CloudFront distribution config
	*
	* See http://docs.amazonwebservices.com/AmazonCloudFront/latest/APIReference/index.html?GetDistribution.html
	*
	* @internal Used to parse the CloudFront DistributionConfig node to an array
	* @param object &$node DOMNode
	* @return array
	*/
	private static function __parseCloudFrontDistributionConfig(&$node)
	{
		if (isset($node->DistributionConfig))
			return self::__parseCloudFrontDistributionConfig($node->DistributionConfig);

		$dist = array();
		if (isset($node->Id, $node->Status, $node->LastModifiedTime, $node->DomainName))
		{
			$dist['id'] = (string)$node->Id;
			$dist['status'] = (string)$node->Status;
			$dist['time'] = strtotime((string)$node->LastModifiedTime);
			$dist['domain'] = (string)$node->DomainName;
		}

		if (isset($node->CallerReference))
			$dist['callerReference'] = (string)$node->CallerReference;

		if (isset($node->Enabled))
			$dist['enabled'] = (string)$node->Enabled == 'true' ? true : false;

		if (isset($node->S3Origin))
		{
			if (isset($node->S3Origin->DNSName))
				$dist['origin'] = (string)$node->S3Origin->DNSName;

			$dist['originAccessIdentity'] = isset($node->S3Origin->OriginAccessIdentity) ?
			(string)$node->S3Origin->OriginAccessIdentity : null;
		}

		$dist['defaultRootObject'] = isset($node->DefaultRootObject) ? (string)$node->DefaultRootObject : null;

		$dist['cnames'] = array();
		if (isset($node->CNAME))
			foreach ($node->CNAME as $cname)
				$dist['cnames'][(string)$cname] = (string)$cname;

		$dist['trustedSigners'] = array();
		if (isset($node->TrustedSigners))
			foreach ($node->TrustedSigners as $signer)
			{
				if (isset($signer->Self))
					$dist['trustedSigners'][''] = 'Self';
				elseif (isset($signer->KeyPairId))
					$dist['trustedSigners'][(string)$signer->KeyPairId] = 'KeyPairId';
				elseif (isset($signer->AwsAccountNumber))
					$dist['trustedSigners'][(string)$signer->AwsAccountNumber] = 'AwsAccountNumber';
			}

		$dist['comment'] = isset($node->Comment) ? (string)$node->Comment : null;
		return $dist;
	}


	/**
	* Grab CloudFront response
	*
	* @internal Used to parse the CloudFront S3Request::getResponse() output
	* @param object &$rest S3Request instance
	* @return object
	*/
	private static function __getCloudFrontResponse(&$rest)
	{
		$rest->getResponse();
		if ($rest->response->error === false && isset($rest->response->body) &&
		is_string($rest->response->body) && substr($rest->response->body, 0, 5) == '<?xml')
		{
			$rest->response->body = simplexml_load_string($rest->response->body);
			// Grab CloudFront errors
			if (isset($rest->response->body->Error, $rest->response->body->Error->Code,
			$rest->response->body->Error->Message))
			{
				$rest->response->error = array(
					'code' => (string)$rest->response->body->Error->Code,
					'message' => (string)$rest->response->body->Error->Message
				);
				unset($rest->response->body);
			}
		}
		return $rest->response;
	}


	/**
	* Get MIME type for file
	*
	* To override the putObject() Content-Type, add it to $requestHeaders
	*
	* To use fileinfo, ensure the MAGIC environment variable is set
	*
	* @internal Used to get mime types
	* @param string &$file File path
	* @return string
	*/
	private static function __getMIMEType(&$file)
	{
		$mime = self::_getMIMETypeByFilename($file);
		if ($mime)
		{
			return $mime;
		}

		// Use fileinfo if available
		if (extension_loaded('fileinfo') && isset($_ENV['MAGIC']) &&
		($finfo = finfo_open(FILEINFO_MIME, $_ENV['MAGIC'])) !== false)
		{
			if (($type = finfo_file($finfo, $file)) !== false)
			{
				// Remove the charset and grab the last content-type
				$type = explode(' ', str_replace('; charset=', ';charset=', $type));
				$type = array_pop($type);
				$type = explode(';', $type);
				$type = trim(array_shift($type));
			}
			finfo_close($finfo);
			if ($type !== false && strlen($type) > 0) return $type;
		}

		return 'application/octet-stream';
	}
	
	/**
	 * Look up mime type using filename to read the file extension. Extensive list of file extensions are supported.
	 * @param string $filename  The filename or URI of the object
	 * @return string  The mime type or null if unknown
	 */
	private static function _getMIMETypeByFilename($filename)
	{
		static $exts = array(
			// compiled from http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types in Oct 2014
			'ez' => 'application/andrew-inset',
			'aw' => 'application/applixware',
			'atom' => 'application/atom+xml',
			'atomcat' => 'application/atomcat+xml',
			'atomsvc' => 'application/atomsvc+xml',
			'ccxml' => 'application/ccxml+xml',
			'cdmia' => 'application/cdmi-capability',
			'cdmic' => 'application/cdmi-container',
			'cdmid' => 'application/cdmi-domain',
			'cdmio' => 'application/cdmi-object',
			'cdmiq' => 'application/cdmi-queue',
			'cu' => 'application/cu-seeme',
			'davmount' => 'application/davmount+xml',
			'dbk' => 'application/docbook+xml',
			'dssc' => 'application/dssc+der',
			'xdssc' => 'application/dssc+xml',
			'ecma' => 'application/ecmascript',
			'emma' => 'application/emma+xml',
			'epub' => 'application/epub+zip',
			'exi' => 'application/exi',
			'pfr' => 'application/font-tdpfr',
			'gml' => 'application/gml+xml',
			'gpx' => 'application/gpx+xml',
			'gxf' => 'application/gxf',
			'stk' => 'application/hyperstudio',
			'ink' => 'application/inkml+xml',
			'inkml' => 'application/inkml+xml',
			'ipfix' => 'application/ipfix',
			'jar' => 'application/java-archive',
			'ser' => 'application/java-serialized-object',
			'class' => 'application/java-vm',
			'js' => 'application/javascript',
			'json' => 'application/json',
			'jsonml' => 'application/jsonml+json',
			'lostxml' => 'application/lost+xml',
			'hqx' => 'application/mac-binhex40',
			'cpt' => 'application/mac-compactpro',
			'mads' => 'application/mads+xml',
			'mrc' => 'application/marc',
			'mrcx' => 'application/marcxml+xml',
			'ma' => 'application/mathematica',
			'nb' => 'application/mathematica',
			'mb' => 'application/mathematica',
			'mathml' => 'application/mathml+xml',
			'mbox' => 'application/mbox',
			'mscml' => 'application/mediaservercontrol+xml',
			'metalink' => 'application/metalink+xml',
			'meta4' => 'application/metalink4+xml',
			'mets' => 'application/mets+xml',
			'mods' => 'application/mods+xml',
			'm21' => 'application/mp21',
			'mp21' => 'application/mp21',
			'mp4s' => 'application/mp4',
			'doc' => 'application/msword',
			'dot' => 'application/msword',
			'mxf' => 'application/mxf',
			'bin' => 'application/octet-stream',
			'dms' => 'application/octet-stream',
			'lrf' => 'application/octet-stream',
			'mar' => 'application/octet-stream',
			'so' => 'application/octet-stream',
			'dist' => 'application/octet-stream',
			'distz' => 'application/octet-stream',
			'pkg' => 'application/octet-stream',
			'bpk' => 'application/octet-stream',
			'dump' => 'application/octet-stream',
			'elc' => 'application/octet-stream',
			'deploy' => 'application/octet-stream',
			'oda' => 'application/oda',
			'opf' => 'application/oebps-package+xml',
			'ogx' => 'application/ogg',
			'omdoc' => 'application/omdoc+xml',
			'onetoc' => 'application/onenote',
			'onetoc2' => 'application/onenote',
			'onetmp' => 'application/onenote',
			'onepkg' => 'application/onenote',
			'oxps' => 'application/oxps',
			'xer' => 'application/patch-ops-error+xml',
			'pdf' => 'application/pdf',
			'pgp' => 'application/pgp-encrypted',
			'asc' => 'application/pgp-signature',
			'sig' => 'application/pgp-signature',
			'prf' => 'application/pics-rules',
			'p10' => 'application/pkcs10',
			'p7m' => 'application/pkcs7-mime',
			'p7c' => 'application/pkcs7-mime',
			'p7s' => 'application/pkcs7-signature',
			'p8' => 'application/pkcs8',
			'ac' => 'application/pkix-attr-cert',
			'cer' => 'application/pkix-cert',
			'crl' => 'application/pkix-crl',
			'pkipath' => 'application/pkix-pkipath',
			'pki' => 'application/pkixcmp',
			'pls' => 'application/pls+xml',
			'ai' => 'application/postscript',
			'eps' => 'application/postscript',
			'ps' => 'application/postscript',
			'cww' => 'application/prs.cww',
			'pskcxml' => 'application/pskc+xml',
			'rdf' => 'application/rdf+xml',
			'rif' => 'application/reginfo+xml',
			'rnc' => 'application/relax-ng-compact-syntax',
			'rl' => 'application/resource-lists+xml',
			'rld' => 'application/resource-lists-diff+xml',
			'rs' => 'application/rls-services+xml',
			'gbr' => 'application/rpki-ghostbusters',
			'mft' => 'application/rpki-manifest',
			'roa' => 'application/rpki-roa',
			'rsd' => 'application/rsd+xml',
			'rss' => 'application/rss+xml',
			'rtf' => 'application/rtf',
			'sbml' => 'application/sbml+xml',
			'scq' => 'application/scvp-cv-request',
			'scs' => 'application/scvp-cv-response',
			'spq' => 'application/scvp-vp-request',
			'spp' => 'application/scvp-vp-response',
			'sdp' => 'application/sdp',
			'setpay' => 'application/set-payment-initiation',
			'setreg' => 'application/set-registration-initiation',
			'shf' => 'application/shf+xml',
			'smi' => 'application/smil+xml',
			'smil' => 'application/smil+xml',
			'rq' => 'application/sparql-query',
			'srx' => 'application/sparql-results+xml',
			'gram' => 'application/srgs',
			'grxml' => 'application/srgs+xml',
			'sru' => 'application/sru+xml',
			'ssdl' => 'application/ssdl+xml',
			'ssml' => 'application/ssml+xml',
			'tei' => 'application/tei+xml',
			'teicorpus' => 'application/tei+xml',
			'tfi' => 'application/thraud+xml',
			'tsd' => 'application/timestamped-data',
			'plb' => 'application/vnd.3gpp.pic-bw-large',
			'psb' => 'application/vnd.3gpp.pic-bw-small',
			'pvb' => 'application/vnd.3gpp.pic-bw-var',
			'tcap' => 'application/vnd.3gpp2.tcap',
			'pwn' => 'application/vnd.3m.post-it-notes',
			'aso' => 'application/vnd.accpac.simply.aso',
			'imp' => 'application/vnd.accpac.simply.imp',
			'acu' => 'application/vnd.acucobol',
			'atc' => 'application/vnd.acucorp',
			'acutc' => 'application/vnd.acucorp',
			'air' => 'application/vnd.adobe.air-application-installer-package+zip',
			'fcdt' => 'application/vnd.adobe.formscentral.fcdt',
			'fxp' => 'application/vnd.adobe.fxp',
			'fxpl' => 'application/vnd.adobe.fxp',
			'xdp' => 'application/vnd.adobe.xdp+xml',
			'xfdf' => 'application/vnd.adobe.xfdf',
			'ahead' => 'application/vnd.ahead.space',
			'azf' => 'application/vnd.airzip.filesecure.azf',
			'azs' => 'application/vnd.airzip.filesecure.azs',
			'azw' => 'application/vnd.amazon.ebook',
			'acc' => 'application/vnd.americandynamics.acc',
			'ami' => 'application/vnd.amiga.ami',
			'apk' => 'application/vnd.android.package-archive',
			'cii' => 'application/vnd.anser-web-certificate-issue-initiation',
			'fti' => 'application/vnd.anser-web-funds-transfer-initiation',
			'atx' => 'application/vnd.antix.game-component',
			'mpkg' => 'application/vnd.apple.installer+xml',
			'm3u8' => 'application/vnd.apple.mpegurl',
			'swi' => 'application/vnd.aristanetworks.swi',
			'iota' => 'application/vnd.astraea-software.iota',
			'aep' => 'application/vnd.audiograph',
			'mpm' => 'application/vnd.blueice.multipass',
			'bmi' => 'application/vnd.bmi',
			'rep' => 'application/vnd.businessobjects',
			'cdxml' => 'application/vnd.chemdraw+xml',
			'mmd' => 'application/vnd.chipnuts.karaoke-mmd',
			'cdy' => 'application/vnd.cinderella',
			'cla' => 'application/vnd.claymore',
			'rp9' => 'application/vnd.cloanto.rp9',
			'c4g' => 'application/vnd.clonk.c4group',
			'c4d' => 'application/vnd.clonk.c4group',
			'c4f' => 'application/vnd.clonk.c4group',
			'c4p' => 'application/vnd.clonk.c4group',
			'c4u' => 'application/vnd.clonk.c4group',
			'c11amc' => 'application/vnd.cluetrust.cartomobile-config',
			'c11amz' => 'application/vnd.cluetrust.cartomobile-config-pkg',
			'csp' => 'application/vnd.commonspace',
			'cdbcmsg' => 'application/vnd.contact.cmsg',
			'cmc' => 'application/vnd.cosmocaller',
			'clkx' => 'application/vnd.crick.clicker',
			'clkk' => 'application/vnd.crick.clicker.keyboard',
			'clkp' => 'application/vnd.crick.clicker.palette',
			'clkt' => 'application/vnd.crick.clicker.template',
			'clkw' => 'application/vnd.crick.clicker.wordbank',
			'wbs' => 'application/vnd.criticaltools.wbs+xml',
			'pml' => 'application/vnd.ctc-posml',
			'ppd' => 'application/vnd.cups-ppd',
			'car' => 'application/vnd.curl.car',
			'pcurl' => 'application/vnd.curl.pcurl',
			'dart' => 'application/vnd.dart',
			'rdz' => 'application/vnd.data-vision.rdz',
			'uvf' => 'application/vnd.dece.data',
			'uvvf' => 'application/vnd.dece.data',
			'uvd' => 'application/vnd.dece.data',
			'uvvd' => 'application/vnd.dece.data',
			'uvt' => 'application/vnd.dece.ttml+xml',
			'uvvt' => 'application/vnd.dece.ttml+xml',
			'uvx' => 'application/vnd.dece.unspecified',
			'uvvx' => 'application/vnd.dece.unspecified',
			'uvz' => 'application/vnd.dece.zip',
			'uvvz' => 'application/vnd.dece.zip',
			'fe_launch' => 'application/vnd.denovo.fcselayout-link',
			'dna' => 'application/vnd.dna',
			'mlp' => 'application/vnd.dolby.mlp',
			'dpg' => 'application/vnd.dpgraph',
			'dfac' => 'application/vnd.dreamfactory',
			'kpxx' => 'application/vnd.ds-keypoint',
			'ait' => 'application/vnd.dvb.ait',
			'svc' => 'application/vnd.dvb.service',
			'geo' => 'application/vnd.dynageo',
			'mag' => 'application/vnd.ecowin.chart',
			'nml' => 'application/vnd.enliven',
			'esf' => 'application/vnd.epson.esf',
			'msf' => 'application/vnd.epson.msf',
			'qam' => 'application/vnd.epson.quickanime',
			'slt' => 'application/vnd.epson.salt',
			'ssf' => 'application/vnd.epson.ssf',
			'es3' => 'application/vnd.eszigno3+xml',
			'et3' => 'application/vnd.eszigno3+xml',
			'ez2' => 'application/vnd.ezpix-album',
			'ez3' => 'application/vnd.ezpix-package',
			'fdf' => 'application/vnd.fdf',
			'mseed' => 'application/vnd.fdsn.mseed',
			'seed' => 'application/vnd.fdsn.seed',
			'dataless' => 'application/vnd.fdsn.seed',
			'gph' => 'application/vnd.flographit',
			'ftc' => 'application/vnd.fluxtime.clip',
			'fm' => 'application/vnd.framemaker',
			'frame' => 'application/vnd.framemaker',
			'maker' => 'application/vnd.framemaker',
			'book' => 'application/vnd.framemaker',
			'fnc' => 'application/vnd.frogans.fnc',
			'ltf' => 'application/vnd.frogans.ltf',
			'fsc' => 'application/vnd.fsc.weblaunch',
			'oas' => 'application/vnd.fujitsu.oasys',
			'oa2' => 'application/vnd.fujitsu.oasys2',
			'oa3' => 'application/vnd.fujitsu.oasys3',
			'fg5' => 'application/vnd.fujitsu.oasysgp',
			'bh2' => 'application/vnd.fujitsu.oasysprs',
			'ddd' => 'application/vnd.fujixerox.ddd',
			'xdw' => 'application/vnd.fujixerox.docuworks',
			'xbd' => 'application/vnd.fujixerox.docuworks.binder',
			'fzs' => 'application/vnd.fuzzysheet',
			'txd' => 'application/vnd.genomatix.tuxedo',
			'ggb' => 'application/vnd.geogebra.file',
			'ggt' => 'application/vnd.geogebra.tool',
			'gex' => 'application/vnd.geometry-explorer',
			'gre' => 'application/vnd.geometry-explorer',
			'gxt' => 'application/vnd.geonext',
			'g2w' => 'application/vnd.geoplan',
			'g3w' => 'application/vnd.geospace',
			'gmx' => 'application/vnd.gmx',
			'kml' => 'application/vnd.google-earth.kml+xml',
			'kmz' => 'application/vnd.google-earth.kmz',
			'gqf' => 'application/vnd.grafeq',
			'gqs' => 'application/vnd.grafeq',
			'gac' => 'application/vnd.groove-account',
			'ghf' => 'application/vnd.groove-help',
			'gim' => 'application/vnd.groove-identity-message',
			'grv' => 'application/vnd.groove-injector',
			'gtm' => 'application/vnd.groove-tool-message',
			'tpl' => 'application/vnd.groove-tool-template',
			'vcg' => 'application/vnd.groove-vcard',
			'hal' => 'application/vnd.hal+xml',
			'zmm' => 'application/vnd.handheld-entertainment+xml',
			'hbci' => 'application/vnd.hbci',
			'les' => 'application/vnd.hhe.lesson-player',
			'hpgl' => 'application/vnd.hp-hpgl',
			'hpid' => 'application/vnd.hp-hpid',
			'hps' => 'application/vnd.hp-hps',
			'jlt' => 'application/vnd.hp-jlyt',
			'pcl' => 'application/vnd.hp-pcl',
			'pclxl' => 'application/vnd.hp-pclxl',
			'sfd-hdstx' => 'application/vnd.hydrostatix.sof-data',
			'mpy' => 'application/vnd.ibm.minipay',
			'afp' => 'application/vnd.ibm.modcap',
			'listafp' => 'application/vnd.ibm.modcap',
			'list3820' => 'application/vnd.ibm.modcap',
			'irm' => 'application/vnd.ibm.rights-management',
			'sc' => 'application/vnd.ibm.secure-container',
			'icc' => 'application/vnd.iccprofile',
			'icm' => 'application/vnd.iccprofile',
			'igl' => 'application/vnd.igloader',
			'ivp' => 'application/vnd.immervision-ivp',
			'ivu' => 'application/vnd.immervision-ivu',
			'igm' => 'application/vnd.insors.igm',
			'xpw' => 'application/vnd.intercon.formnet',
			'xpx' => 'application/vnd.intercon.formnet',
			'i2g' => 'application/vnd.intergeo',
			'qbo' => 'application/vnd.intu.qbo',
			'qfx' => 'application/vnd.intu.qfx',
			'rcprofile' => 'application/vnd.ipunplugged.rcprofile',
			'irp' => 'application/vnd.irepository.package+xml',
			'xpr' => 'application/vnd.is-xpr',
			'fcs' => 'application/vnd.isac.fcs',
			'jam' => 'application/vnd.jam',
			'rms' => 'application/vnd.jcp.javame.midlet-rms',
			'jisp' => 'application/vnd.jisp',
			'joda' => 'application/vnd.joost.joda-archive',
			'ktz' => 'application/vnd.kahootz',
			'ktr' => 'application/vnd.kahootz',
			'karbon' => 'application/vnd.kde.karbon',
			'chrt' => 'application/vnd.kde.kchart',
			'kfo' => 'application/vnd.kde.kformula',
			'flw' => 'application/vnd.kde.kivio',
			'kon' => 'application/vnd.kde.kontour',
			'kpr' => 'application/vnd.kde.kpresenter',
			'kpt' => 'application/vnd.kde.kpresenter',
			'ksp' => 'application/vnd.kde.kspread',
			'kwd' => 'application/vnd.kde.kword',
			'kwt' => 'application/vnd.kde.kword',
			'htke' => 'application/vnd.kenameaapp',
			'kia' => 'application/vnd.kidspiration',
			'kne' => 'application/vnd.kinar',
			'knp' => 'application/vnd.kinar',
			'skp' => 'application/vnd.koan',
			'skd' => 'application/vnd.koan',
			'skt' => 'application/vnd.koan',
			'skm' => 'application/vnd.koan',
			'sse' => 'application/vnd.kodak-descriptor',
			'lasxml' => 'application/vnd.las.las+xml',
			'lbd' => 'application/vnd.llamagraphics.life-balance.desktop',
			'lbe' => 'application/vnd.llamagraphics.life-balance.exchange+xml',
			'123' => 'application/vnd.lotus-1-2-3',
			'apr' => 'application/vnd.lotus-approach',
			'pre' => 'application/vnd.lotus-freelance',
			'nsf' => 'application/vnd.lotus-notes',
			'org' => 'application/vnd.lotus-organizer',
			'scm' => 'application/vnd.lotus-screencam',
			'lwp' => 'application/vnd.lotus-wordpro',
			'portpkg' => 'application/vnd.macports.portpkg',
			'mcd' => 'application/vnd.mcd',
			'mc1' => 'application/vnd.medcalcdata',
			'cdkey' => 'application/vnd.mediastation.cdkey',
			'mwf' => 'application/vnd.mfer',
			'mfm' => 'application/vnd.mfmp',
			'flo' => 'application/vnd.micrografx.flo',
			'igx' => 'application/vnd.micrografx.igx',
			'mif' => 'application/vnd.mif',
			'daf' => 'application/vnd.mobius.daf',
			'dis' => 'application/vnd.mobius.dis',
			'mbk' => 'application/vnd.mobius.mbk',
			'mqy' => 'application/vnd.mobius.mqy',
			'msl' => 'application/vnd.mobius.msl',
			'plc' => 'application/vnd.mobius.plc',
			'txf' => 'application/vnd.mobius.txf',
			'mpn' => 'application/vnd.mophun.application',
			'mpc' => 'application/vnd.mophun.certificate',
			'xul' => 'application/vnd.mozilla.xul+xml',
			'cil' => 'application/vnd.ms-artgalry',
			'cab' => 'application/vnd.ms-cab-compressed',
			'xls' => 'application/vnd.ms-excel',
			'xlm' => 'application/vnd.ms-excel',
			'xla' => 'application/vnd.ms-excel',
			'xlc' => 'application/vnd.ms-excel',
			'xlt' => 'application/vnd.ms-excel',
			'xlw' => 'application/vnd.ms-excel',
			'xlam' => 'application/vnd.ms-excel.addin.macroenabled.12',
			'xlsb' => 'application/vnd.ms-excel.sheet.binary.macroenabled.12',
			'xlsm' => 'application/vnd.ms-excel.sheet.macroenabled.12',
			'xltm' => 'application/vnd.ms-excel.template.macroenabled.12',
			'eot' => 'application/vnd.ms-fontobject',
			'chm' => 'application/vnd.ms-htmlhelp',
			'ims' => 'application/vnd.ms-ims',
			'lrm' => 'application/vnd.ms-lrm',
			'thmx' => 'application/vnd.ms-officetheme',
			'cat' => 'application/vnd.ms-pki.seccat',
			'stl' => 'application/vnd.ms-pki.stl',
			'ppt' => 'application/vnd.ms-powerpoint',
			'pps' => 'application/vnd.ms-powerpoint',
			'pot' => 'application/vnd.ms-powerpoint',
			'ppam' => 'application/vnd.ms-powerpoint.addin.macroenabled.12',
			'pptm' => 'application/vnd.ms-powerpoint.presentation.macroenabled.12',
			'sldm' => 'application/vnd.ms-powerpoint.slide.macroenabled.12',
			'ppsm' => 'application/vnd.ms-powerpoint.slideshow.macroenabled.12',
			'potm' => 'application/vnd.ms-powerpoint.template.macroenabled.12',
			'mpp' => 'application/vnd.ms-project',
			'mpt' => 'application/vnd.ms-project',
			'docm' => 'application/vnd.ms-word.document.macroenabled.12',
			'dotm' => 'application/vnd.ms-word.template.macroenabled.12',
			'wps' => 'application/vnd.ms-works',
			'wks' => 'application/vnd.ms-works',
			'wcm' => 'application/vnd.ms-works',
			'wdb' => 'application/vnd.ms-works',
			'wpl' => 'application/vnd.ms-wpl',
			'xps' => 'application/vnd.ms-xpsdocument',
			'mseq' => 'application/vnd.mseq',
			'mus' => 'application/vnd.musician',
			'msty' => 'application/vnd.muvee.style',
			'taglet' => 'application/vnd.mynfc',
			'nlu' => 'application/vnd.neurolanguage.nlu',
			'ntf' => 'application/vnd.nitf',
			'nitf' => 'application/vnd.nitf',
			'nnd' => 'application/vnd.noblenet-directory',
			'nns' => 'application/vnd.noblenet-sealer',
			'nnw' => 'application/vnd.noblenet-web',
			'ngdat' => 'application/vnd.nokia.n-gage.data',
			'n-gage' => 'application/vnd.nokia.n-gage.symbian.install',
			'rpst' => 'application/vnd.nokia.radio-preset',
			'rpss' => 'application/vnd.nokia.radio-presets',
			'edm' => 'application/vnd.novadigm.edm',
			'edx' => 'application/vnd.novadigm.edx',
			'ext' => 'application/vnd.novadigm.ext',
			'odc' => 'application/vnd.oasis.opendocument.chart',
			'otc' => 'application/vnd.oasis.opendocument.chart-template',
			'odb' => 'application/vnd.oasis.opendocument.database',
			'odf' => 'application/vnd.oasis.opendocument.formula',
			'odft' => 'application/vnd.oasis.opendocument.formula-template',
			'odg' => 'application/vnd.oasis.opendocument.graphics',
			'otg' => 'application/vnd.oasis.opendocument.graphics-template',
			'odi' => 'application/vnd.oasis.opendocument.image',
			'oti' => 'application/vnd.oasis.opendocument.image-template',
			'odp' => 'application/vnd.oasis.opendocument.presentation',
			'otp' => 'application/vnd.oasis.opendocument.presentation-template',
			'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
			'ots' => 'application/vnd.oasis.opendocument.spreadsheet-template',
			'odt' => 'application/vnd.oasis.opendocument.text',
			'odm' => 'application/vnd.oasis.opendocument.text-master',
			'ott' => 'application/vnd.oasis.opendocument.text-template',
			'oth' => 'application/vnd.oasis.opendocument.text-web',
			'xo' => 'application/vnd.olpc-sugar',
			'dd2' => 'application/vnd.oma.dd2+xml',
			'oxt' => 'application/vnd.openofficeorg.extension',
			'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
			'sldx' => 'application/vnd.openxmlformats-officedocument.presentationml.slide',
			'ppsx' => 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
			'potx' => 'application/vnd.openxmlformats-officedocument.presentationml.template',
			'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
			'xltx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
			'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
			'dotx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
			'mgp' => 'application/vnd.osgeo.mapguide.package',
			'dp' => 'application/vnd.osgi.dp',
			'esa' => 'application/vnd.osgi.subsystem',
			'pdb' => 'application/vnd.palm',
			'pqa' => 'application/vnd.palm',
			'oprc' => 'application/vnd.palm',
			'paw' => 'application/vnd.pawaafile',
			'str' => 'application/vnd.pg.format',
			'ei6' => 'application/vnd.pg.osasli',
			'efif' => 'application/vnd.picsel',
			'wg' => 'application/vnd.pmi.widget',
			'plf' => 'application/vnd.pocketlearn',
			'pbd' => 'application/vnd.powerbuilder6',
			'box' => 'application/vnd.previewsystems.box',
			'mgz' => 'application/vnd.proteus.magazine',
			'qps' => 'application/vnd.publishare-delta-tree',
			'ptid' => 'application/vnd.pvi.ptid1',
			'qxd' => 'application/vnd.quark.quarkxpress',
			'qxt' => 'application/vnd.quark.quarkxpress',
			'qwd' => 'application/vnd.quark.quarkxpress',
			'qwt' => 'application/vnd.quark.quarkxpress',
			'qxl' => 'application/vnd.quark.quarkxpress',
			'qxb' => 'application/vnd.quark.quarkxpress',
			'bed' => 'application/vnd.realvnc.bed',
			'mxl' => 'application/vnd.recordare.musicxml',
			'musicxml' => 'application/vnd.recordare.musicxml+xml',
			'cryptonote' => 'application/vnd.rig.cryptonote',
			'cod' => 'application/vnd.rim.cod',
			'rm' => 'application/vnd.rn-realmedia',
			'rmvb' => 'application/vnd.rn-realmedia-vbr',
			'link66' => 'application/vnd.route66.link66+xml',
			'st' => 'application/vnd.sailingtracker.track',
			'see' => 'application/vnd.seemail',
			'sema' => 'application/vnd.sema',
			'semd' => 'application/vnd.semd',
			'semf' => 'application/vnd.semf',
			'ifm' => 'application/vnd.shana.informed.formdata',
			'itp' => 'application/vnd.shana.informed.formtemplate',
			'iif' => 'application/vnd.shana.informed.interchange',
			'ipk' => 'application/vnd.shana.informed.package',
			'twd' => 'application/vnd.simtech-mindmapper',
			'twds' => 'application/vnd.simtech-mindmapper',
			'mmf' => 'application/vnd.smaf',
			'teacher' => 'application/vnd.smart.teacher',
			'sdkm' => 'application/vnd.solent.sdkm+xml',
			'sdkd' => 'application/vnd.solent.sdkm+xml',
			'dxp' => 'application/vnd.spotfire.dxp',
			'sfs' => 'application/vnd.spotfire.sfs',
			'sdc' => 'application/vnd.stardivision.calc',
			'sda' => 'application/vnd.stardivision.draw',
			'sdd' => 'application/vnd.stardivision.impress',
			'smf' => 'application/vnd.stardivision.math',
			'sdw' => 'application/vnd.stardivision.writer',
			'vor' => 'application/vnd.stardivision.writer',
			'sgl' => 'application/vnd.stardivision.writer-global',
			'smzip' => 'application/vnd.stepmania.package',
			'sm' => 'application/vnd.stepmania.stepchart',
			'sxc' => 'application/vnd.sun.xml.calc',
			'stc' => 'application/vnd.sun.xml.calc.template',
			'sxd' => 'application/vnd.sun.xml.draw',
			'std' => 'application/vnd.sun.xml.draw.template',
			'sxi' => 'application/vnd.sun.xml.impress',
			'sti' => 'application/vnd.sun.xml.impress.template',
			'sxm' => 'application/vnd.sun.xml.math',
			'sxw' => 'application/vnd.sun.xml.writer',
			'sxg' => 'application/vnd.sun.xml.writer.global',
			'stw' => 'application/vnd.sun.xml.writer.template',
			'sus' => 'application/vnd.sus-calendar',
			'susp' => 'application/vnd.sus-calendar',
			'svd' => 'application/vnd.svd',
			'sis' => 'application/vnd.symbian.install',
			'sisx' => 'application/vnd.symbian.install',
			'xsm' => 'application/vnd.syncml+xml',
			'bdm' => 'application/vnd.syncml.dm+wbxml',
			'xdm' => 'application/vnd.syncml.dm+xml',
			'tao' => 'application/vnd.tao.intent-module-archive',
			'pcap' => 'application/vnd.tcpdump.pcap',
			'cap' => 'application/vnd.tcpdump.pcap',
			'dmp' => 'application/vnd.tcpdump.pcap',
			'tmo' => 'application/vnd.tmobile-livetv',
			'tpt' => 'application/vnd.trid.tpt',
			'mxs' => 'application/vnd.triscape.mxs',
			'tra' => 'application/vnd.trueapp',
			'ufd' => 'application/vnd.ufdl',
			'ufdl' => 'application/vnd.ufdl',
			'utz' => 'application/vnd.uiq.theme',
			'umj' => 'application/vnd.umajin',
			'unityweb' => 'application/vnd.unity',
			'uoml' => 'application/vnd.uoml+xml',
			'vcx' => 'application/vnd.vcx',
			'vsd' => 'application/vnd.visio',
			'vst' => 'application/vnd.visio',
			'vss' => 'application/vnd.visio',
			'vsw' => 'application/vnd.visio',
			'vis' => 'application/vnd.visionary',
			'vsf' => 'application/vnd.vsf',
			'wbxml' => 'application/vnd.wap.wbxml',
			'wmlc' => 'application/vnd.wap.wmlc',
			'wmlsc' => 'application/vnd.wap.wmlscriptc',
			'wtb' => 'application/vnd.webturbo',
			'nbp' => 'application/vnd.wolfram.player',
			'wpd' => 'application/vnd.wordperfect',
			'wqd' => 'application/vnd.wqd',
			'stf' => 'application/vnd.wt.stf',
			'xar' => 'application/vnd.xara',
			'xfdl' => 'application/vnd.xfdl',
			'hvd' => 'application/vnd.yamaha.hv-dic',
			'hvs' => 'application/vnd.yamaha.hv-script',
			'hvp' => 'application/vnd.yamaha.hv-voice',
			'osf' => 'application/vnd.yamaha.openscoreformat',
			'osfpvg' => 'application/vnd.yamaha.openscoreformat.osfpvg+xml',
			'saf' => 'application/vnd.yamaha.smaf-audio',
			'spf' => 'application/vnd.yamaha.smaf-phrase',
			'cmp' => 'application/vnd.yellowriver-custom-menu',
			'zir' => 'application/vnd.zul',
			'zirz' => 'application/vnd.zul',
			'zaz' => 'application/vnd.zzazz.deck+xml',
			'vxml' => 'application/voicexml+xml',
			'wgt' => 'application/widget',
			'hlp' => 'application/winhlp',
			'wsdl' => 'application/wsdl+xml',
			'wspolicy' => 'application/wspolicy+xml',
			'7z' => 'application/x-7z-compressed',
			'abw' => 'application/x-abiword',
			'ace' => 'application/x-ace-compressed',
			'dmg' => 'application/x-apple-diskimage',
			'aab' => 'application/x-authorware-bin',
			'x32' => 'application/x-authorware-bin',
			'u32' => 'application/x-authorware-bin',
			'vox' => 'application/x-authorware-bin',
			'aam' => 'application/x-authorware-map',
			'aas' => 'application/x-authorware-seg',
			'bcpio' => 'application/x-bcpio',
			'torrent' => 'application/x-bittorrent',
			'blb' => 'application/x-blorb',
			'blorb' => 'application/x-blorb',
			'bz' => 'application/x-bzip',
			'bz2' => 'application/x-bzip2',
			'boz' => 'application/x-bzip2',
			'cbr' => 'application/x-cbr',
			'cba' => 'application/x-cbr',
			'cbt' => 'application/x-cbr',
			'cbz' => 'application/x-cbr',
			'cb7' => 'application/x-cbr',
			'vcd' => 'application/x-cdlink',
			'cfs' => 'application/x-cfs-compressed',
			'chat' => 'application/x-chat',
			'pgn' => 'application/x-chess-pgn',
			'nsc' => 'application/x-conference',
			'cpio' => 'application/x-cpio',
			'csh' => 'application/x-csh',
			'deb' => 'application/x-debian-package',
			'udeb' => 'application/x-debian-package',
			'dgc' => 'application/x-dgc-compressed',
			'dir' => 'application/x-director',
			'dcr' => 'application/x-director',
			'dxr' => 'application/x-director',
			'cst' => 'application/x-director',
			'cct' => 'application/x-director',
			'cxt' => 'application/x-director',
			'w3d' => 'application/x-director',
			'fgd' => 'application/x-director',
			'swa' => 'application/x-director',
			'wad' => 'application/x-doom',
			'ncx' => 'application/x-dtbncx+xml',
			'dtb' => 'application/x-dtbook+xml',
			'res' => 'application/x-dtbresource+xml',
			'dvi' => 'application/x-dvi',
			'evy' => 'application/x-envoy',
			'eva' => 'application/x-eva',
			'bdf' => 'application/x-font-bdf',
			'gsf' => 'application/x-font-ghostscript',
			'psf' => 'application/x-font-linux-psf',
			'otf' => 'application/x-font-otf',
			'pcf' => 'application/x-font-pcf',
			'snf' => 'application/x-font-snf',
			'ttf' => 'application/x-font-ttf',
			'ttc' => 'application/x-font-ttf',
			'pfa' => 'application/x-font-type1',
			'pfb' => 'application/x-font-type1',
			'pfm' => 'application/x-font-type1',
			'afm' => 'application/x-font-type1',
			'woff' => 'application/font-woff',
			'arc' => 'application/x-freearc',
			'spl' => 'application/x-futuresplash',
			'gca' => 'application/x-gca-compressed',
			'ulx' => 'application/x-glulx',
			'gnumeric' => 'application/x-gnumeric',
			'gramps' => 'application/x-gramps-xml',
			'gtar' => 'application/x-gtar',
			'hdf' => 'application/x-hdf',
			'install' => 'application/x-install-instructions',
			'iso' => 'application/x-iso9660-image',
			'jnlp' => 'application/x-java-jnlp-file',
			'latex' => 'application/x-latex',
			'lzh' => 'application/x-lzh-compressed',
			'lha' => 'application/x-lzh-compressed',
			'mie' => 'application/x-mie',
			'prc' => 'application/x-mobipocket-ebook',
			'mobi' => 'application/x-mobipocket-ebook',
			'application' => 'application/x-ms-application',
			'lnk' => 'application/x-ms-shortcut',
			'wmd' => 'application/x-ms-wmd',
			'wmz' => 'application/x-msmetafile',
			'xbap' => 'application/x-ms-xbap',
			'mdb' => 'application/x-msaccess',
			'obd' => 'application/x-msbinder',
			'crd' => 'application/x-mscardfile',
			'clp' => 'application/x-msclip',
			'exe' => 'application/x-msdownload',
			'dll' => 'application/x-msdownload',
			'com' => 'application/x-msdownload',
			'bat' => 'application/x-msdownload',
			'msi' => 'application/x-msdownload',
			'mvb' => 'application/x-msmediaview',
			'm13' => 'application/x-msmediaview',
			'm14' => 'application/x-msmediaview',
			'wmf' => 'application/x-msmetafile',
			'emf' => 'application/x-msmetafile',
			'emz' => 'application/x-msmetafile',
			'mny' => 'application/x-msmoney',
			'pub' => 'application/x-mspublisher',
			'scd' => 'application/x-msschedule',
			'trm' => 'application/x-msterminal',
			'wri' => 'application/x-mswrite',
			'nc' => 'application/x-netcdf',
			'cdf' => 'application/x-netcdf',
			'nzb' => 'application/x-nzb',
			'p12' => 'application/x-pkcs12',
			'pfx' => 'application/x-pkcs12',
			'p7b' => 'application/x-pkcs7-certificates',
			'spc' => 'application/x-pkcs7-certificates',
			'p7r' => 'application/x-pkcs7-certreqresp',
			'rar' => 'application/x-rar-compressed',
			'ris' => 'application/x-research-info-systems',
			'sh' => 'application/x-sh',
			'shar' => 'application/x-shar',
			'swf' => 'application/x-shockwave-flash',
			'xap' => 'application/x-silverlight-app',
			'sql' => 'application/x-sql',
			'sit' => 'application/x-stuffit',
			'sitx' => 'application/x-stuffitx',
			'srt' => 'application/x-subrip',
			'sv4cpio' => 'application/x-sv4cpio',
			'sv4crc' => 'application/x-sv4crc',
			't3' => 'application/x-t3vm-image',
			'gam' => 'application/x-tads',
			'tar' => 'application/x-tar',
			'tcl' => 'application/x-tcl',
			'tex' => 'application/x-tex',
			'tfm' => 'application/x-tex-tfm',
			'texinfo' => 'application/x-texinfo',
			'texi' => 'application/x-texinfo',
			'obj' => 'application/x-tgif',
			'ustar' => 'application/x-ustar',
			'src' => 'application/x-wais-source',
			'der' => 'application/x-x509-ca-cert',
			'crt' => 'application/x-x509-ca-cert',
			'fig' => 'application/x-xfig',
			'xlf' => 'application/x-xliff+xml',
			'xpi' => 'application/x-xpinstall',
			'xz' => 'application/x-xz',
			'z1' => 'application/x-zmachine',
			'z2' => 'application/x-zmachine',
			'z3' => 'application/x-zmachine',
			'z4' => 'application/x-zmachine',
			'z5' => 'application/x-zmachine',
			'z6' => 'application/x-zmachine',
			'z7' => 'application/x-zmachine',
			'z8' => 'application/x-zmachine',
			'xaml' => 'application/xaml+xml',
			'xdf' => 'application/xcap-diff+xml',
			'xenc' => 'application/xenc+xml',
			'xhtml' => 'application/xhtml+xml',
			'xht' => 'application/xhtml+xml',
			'xml' => 'application/xml',
			'xsl' => 'application/xml',
			'dtd' => 'application/xml-dtd',
			'xop' => 'application/xop+xml',
			'xpl' => 'application/xproc+xml',
			'xslt' => 'application/xslt+xml',
			'xspf' => 'application/xspf+xml',
			'mxml' => 'application/xv+xml',
			'xhvml' => 'application/xv+xml',
			'xvml' => 'application/xv+xml',
			'xvm' => 'application/xv+xml',
			'yang' => 'application/yang',
			'yin' => 'application/yin+xml',
			'zip' => 'application/zip',
			'adp' => 'audio/adpcm',
			'au' => 'audio/basic',
			'snd' => 'audio/basic',
			'mid' => 'audio/midi',
			'midi' => 'audio/midi',
			'kar' => 'audio/midi',
			'rmi' => 'audio/midi',
			'mp4a' => 'audio/mp4',
			'mpga' => 'audio/mpeg',
			'mp2' => 'audio/mpeg',
			'mp2a' => 'audio/mpeg',
			'mp3' => 'audio/mpeg',
			'm2a' => 'audio/mpeg',
			'm3a' => 'audio/mpeg',
			'oga' => 'audio/ogg',
			'ogg' => 'audio/ogg',
			'spx' => 'audio/ogg',
			's3m' => 'audio/s3m',
			'sil' => 'audio/silk',
			'uva' => 'audio/vnd.dece.audio',
			'uvva' => 'audio/vnd.dece.audio',
			'eol' => 'audio/vnd.digital-winds',
			'dra' => 'audio/vnd.dra',
			'dts' => 'audio/vnd.dts',
			'dtshd' => 'audio/vnd.dts.hd',
			'lvp' => 'audio/vnd.lucent.voice',
			'pya' => 'audio/vnd.ms-playready.media.pya',
			'ecelp4800' => 'audio/vnd.nuera.ecelp4800',
			'ecelp7470' => 'audio/vnd.nuera.ecelp7470',
			'ecelp9600' => 'audio/vnd.nuera.ecelp9600',
			'rip' => 'audio/vnd.rip',
			'weba' => 'audio/webm',
			'aac' => 'audio/x-aac',
			'aif' => 'audio/x-aiff',
			'aiff' => 'audio/x-aiff',
			'aifc' => 'audio/x-aiff',
			'caf' => 'audio/x-caf',
			'flac' => 'audio/x-flac',
			'mka' => 'audio/x-matroska',
			'm3u' => 'audio/x-mpegurl',
			'wax' => 'audio/x-ms-wax',
			'wma' => 'audio/x-ms-wma',
			'ram' => 'audio/x-pn-realaudio',
			'ra' => 'audio/x-pn-realaudio',
			'rmp' => 'audio/x-pn-realaudio-plugin',
			'wav' => 'audio/x-wav',
			'xm' => 'audio/xm',
			'cdx' => 'chemical/x-cdx',
			'cif' => 'chemical/x-cif',
			'cmdf' => 'chemical/x-cmdf',
			'cml' => 'chemical/x-cml',
			'csml' => 'chemical/x-csml',
			'xyz' => 'chemical/x-xyz',
			'bmp' => 'image/bmp',
			'cgm' => 'image/cgm',
			'g3' => 'image/g3fax',
			'gif' => 'image/gif',
			'ief' => 'image/ief',
			'jpeg' => 'image/jpeg',
			'jpg' => 'image/jpeg',
			'jpe' => 'image/jpeg',
			'ktx' => 'image/ktx',
			'png' => 'image/png',
			'btif' => 'image/prs.btif',
			'sgi' => 'image/sgi',
			'svg' => 'image/svg+xml',
			'svgz' => 'image/svg+xml',
			'tiff' => 'image/tiff',
			'tif' => 'image/tiff',
			'psd' => 'image/vnd.adobe.photoshop',
			'uvi' => 'image/vnd.dece.graphic',
			'uvvi' => 'image/vnd.dece.graphic',
			'uvg' => 'image/vnd.dece.graphic',
			'uvvg' => 'image/vnd.dece.graphic',
			'sub' => 'text/vnd.dvb.subtitle',
			'djvu' => 'image/vnd.djvu',
			'djv' => 'image/vnd.djvu',
			'dwg' => 'image/vnd.dwg',
			'dxf' => 'image/vnd.dxf',
			'fbs' => 'image/vnd.fastbidsheet',
			'fpx' => 'image/vnd.fpx',
			'fst' => 'image/vnd.fst',
			'mmr' => 'image/vnd.fujixerox.edmics-mmr',
			'rlc' => 'image/vnd.fujixerox.edmics-rlc',
			'mdi' => 'image/vnd.ms-modi',
			'wdp' => 'image/vnd.ms-photo',
			'npx' => 'image/vnd.net-fpx',
			'wbmp' => 'image/vnd.wap.wbmp',
			'xif' => 'image/vnd.xiff',
			'webp' => 'image/webp',
			'3ds' => 'image/x-3ds',
			'ras' => 'image/x-cmu-raster',
			'cmx' => 'image/x-cmx',
			'fh' => 'image/x-freehand',
			'fhc' => 'image/x-freehand',
			'fh4' => 'image/x-freehand',
			'fh5' => 'image/x-freehand',
			'fh7' => 'image/x-freehand',
			'ico' => 'image/x-icon',
			'sid' => 'image/x-mrsid-image',
			'pcx' => 'image/x-pcx',
			'pic' => 'image/x-pict',
			'pct' => 'image/x-pict',
			'pnm' => 'image/x-portable-anymap',
			'pbm' => 'image/x-portable-bitmap',
			'pgm' => 'image/x-portable-graymap',
			'ppm' => 'image/x-portable-pixmap',
			'rgb' => 'image/x-rgb',
			'tga' => 'image/x-tga',
			'xbm' => 'image/x-xbitmap',
			'xpm' => 'image/x-xpixmap',
			'xwd' => 'image/x-xwindowdump',
			'eml' => 'message/rfc822',
			'mime' => 'message/rfc822',
			'igs' => 'model/iges',
			'iges' => 'model/iges',
			'msh' => 'model/mesh',
			'mesh' => 'model/mesh',
			'silo' => 'model/mesh',
			'dae' => 'model/vnd.collada+xml',
			'dwf' => 'model/vnd.dwf',
			'gdl' => 'model/vnd.gdl',
			'gtw' => 'model/vnd.gtw',
			'mts' => 'model/vnd.mts',
			'vtu' => 'model/vnd.vtu',
			'wrl' => 'model/vrml',
			'vrml' => 'model/vrml',
			'x3db' => 'model/x3d+binary',
			'x3dbz' => 'model/x3d+binary',
			'x3dv' => 'model/x3d+vrml',
			'x3dvz' => 'model/x3d+vrml',
			'x3d' => 'model/x3d+xml',
			'x3dz' => 'model/x3d+xml',
			'appcache' => 'text/cache-manifest',
			'ics' => 'text/calendar',
			'ifb' => 'text/calendar',
			'css' => 'text/css',
			'csv' => 'text/csv',
			'html' => 'text/html',
			'htm' => 'text/html',
			'n3' => 'text/n3',
			'txt' => 'text/plain',
			'text' => 'text/plain',
			'conf' => 'text/plain',
			'def' => 'text/plain',
			'list' => 'text/plain',
			'log' => 'text/plain',
			'in' => 'text/plain',
			'dsc' => 'text/prs.lines.tag',
			'rtx' => 'text/richtext',
			'sgml' => 'text/sgml',
			'sgm' => 'text/sgml',
			'tsv' => 'text/tab-separated-values',
			't' => 'text/troff',
			'tr' => 'text/troff',
			'roff' => 'text/troff',
			'man' => 'text/troff',
			'me' => 'text/troff',
			'ms' => 'text/troff',
			'ttl' => 'text/turtle',
			'uri' => 'text/uri-list',
			'uris' => 'text/uri-list',
			'urls' => 'text/uri-list',
			'vcard' => 'text/vcard',
			'curl' => 'text/vnd.curl',
			'dcurl' => 'text/vnd.curl.dcurl',
			'scurl' => 'text/vnd.curl.scurl',
			'mcurl' => 'text/vnd.curl.mcurl',
			'fly' => 'text/vnd.fly',
			'flx' => 'text/vnd.fmi.flexstor',
			'gv' => 'text/vnd.graphviz',
			'3dml' => 'text/vnd.in3d.3dml',
			'spot' => 'text/vnd.in3d.spot',
			'jad' => 'text/vnd.sun.j2me.app-descriptor',
			'wml' => 'text/vnd.wap.wml',
			'wmls' => 'text/vnd.wap.wmlscript',
			's' => 'text/x-asm',
			'asm' => 'text/x-asm',
			'c' => 'text/x-c',
			'cc' => 'text/x-c',
			'cxx' => 'text/x-c',
			'cpp' => 'text/x-c',
			'h' => 'text/x-c',
			'hh' => 'text/x-c',
			'dic' => 'text/x-c',
			'f' => 'text/x-fortran',
			'for' => 'text/x-fortran',
			'f77' => 'text/x-fortran',
			'f90' => 'text/x-fortran',
			'java' => 'text/x-java-source',
			'opml' => 'text/x-opml',
			'p' => 'text/x-pascal',
			'pas' => 'text/x-pascal',
			'nfo' => 'text/x-nfo',
			'etx' => 'text/x-setext',
			'sfv' => 'text/x-sfv',
			'uu' => 'text/x-uuencode',
			'vcs' => 'text/x-vcalendar',
			'vcf' => 'text/x-vcard',
			'3gp' => 'video/3gpp',
			'3g2' => 'video/3gpp2',
			'h261' => 'video/h261',
			'h263' => 'video/h263',
			'h264' => 'video/h264',
			'jpgv' => 'video/jpeg',
			'jpm' => 'video/jpm',
			'jpgm' => 'video/jpm',
			'mj2' => 'video/mj2',
			'mjp2' => 'video/mj2',
			'mp4' => 'video/mp4',
			'mp4v' => 'video/mp4',
			'mpg4' => 'video/mp4',
			'mpeg' => 'video/mpeg',
			'mpg' => 'video/mpeg',
			'mpe' => 'video/mpeg',
			'm1v' => 'video/mpeg',
			'm2v' => 'video/mpeg',
			'ogv' => 'video/ogg',
			'qt' => 'video/quicktime',
			'mov' => 'video/quicktime',
			'uvh' => 'video/vnd.dece.hd',
			'uvvh' => 'video/vnd.dece.hd',
			'uvm' => 'video/vnd.dece.mobile',
			'uvvm' => 'video/vnd.dece.mobile',
			'uvp' => 'video/vnd.dece.pd',
			'uvvp' => 'video/vnd.dece.pd',
			'uvs' => 'video/vnd.dece.sd',
			'uvvs' => 'video/vnd.dece.sd',
			'uvv' => 'video/vnd.dece.video',
			'uvvv' => 'video/vnd.dece.video',
			'dvb' => 'video/vnd.dvb.file',
			'fvt' => 'video/vnd.fvt',
			'mxu' => 'video/vnd.mpegurl',
			'm4u' => 'video/vnd.mpegurl',
			'pyv' => 'video/vnd.ms-playready.media.pyv',
			'uvu' => 'video/vnd.uvvu.mp4',
			'uvvu' => 'video/vnd.uvvu.mp4',
			'viv' => 'video/vnd.vivo',
			'webm' => 'video/webm',
			'f4v' => 'video/x-f4v',
			'fli' => 'video/x-fli',
			'flv' => 'video/x-flv',
			'm4v' => 'video/x-m4v',
			'mkv' => 'video/x-matroska',
			'mk3d' => 'video/x-matroska',
			'mks' => 'video/x-matroska',
			'mng' => 'video/x-mng',
			'asf' => 'video/x-ms-asf',
			'asx' => 'video/x-ms-asf',
			'vob' => 'video/x-ms-vob',
			'wm' => 'video/x-ms-wm',
			'wmv' => 'video/x-ms-wmv',
			'wmx' => 'video/x-ms-wmx',
			'wvx' => 'video/x-ms-wvx',
			'avi' => 'video/x-msvideo',
			'movie' => 'video/x-sgi-movie',
			'smv' => 'video/x-smv',
			'ice' => 'x-conference/x-cooltalk',
		);

		$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
		if (isset($exts[$ext]))
		{
			return $exts[$ext];
		}
		return null;
	}

	/**
	* Get the current time
	*
	* @internal Used to apply offsets to sytem time
	* @return integer
	*/
	public static function __getTime()
	{
		return time() + self::$__timeOffset;
	}


	/**
	* Generate the auth string: "AWS AccessKey:Signature"
	*
	* @internal Used by S3Request::getResponse()
	* @param string $string String to sign
	* @return string
	*/
	public static function __getSignature($string)
	{
		return 'AWS '.self::$__accessKey.':'.self::__getHash($string);
	}


	/**
	* Creates a HMAC-SHA1 hash
	*
	* This uses the hash extension if loaded
	*
	* @internal Used by __getSignature()
	* @param string $string String to sign
	* @return string
	*/
	private static function __getHash($string)
	{
		return base64_encode(extension_loaded('hash') ?
		hash_hmac('sha1', $string, self::$__secretKey, true) : pack('H*', sha1(
		(str_pad(self::$__secretKey, 64, chr(0x00)) ^ (str_repeat(chr(0x5c), 64))) .
		pack('H*', sha1((str_pad(self::$__secretKey, 64, chr(0x00)) ^
		(str_repeat(chr(0x36), 64))) . $string)))));
	}

}

/**
 * S3 Request class 
 *
 * @link http://undesigned.org.za/2007/10/22/amazon-s3-php-class
 * @version 0.5.0-dev
 */
final class S3Request
{
	/**
	 * AWS URI
	 *
	 * @var string
	 * @access pricate
	 */
	private $endpoint;
	
	/**
	 * Verb
	 *
	 * @var string
	 * @access private
	 */
	private $verb;
	
	/**
	 * S3 bucket name
	 *
	 * @var string
	 * @access private
	 */
	private $bucket;
	
	/**
	 * Object URI
	 *
	 * @var string
	 * @access private
	 */
	private $uri;
	
	/**
	 * Final object URI
	 *
	 * @var string
	 * @access private
	 */
	private $resource = '';
	
	/**
	 * Additional request parameters
	 *
	 * @var array
	 * @access private
	 */
	private $parameters = array();
	
	/**
	 * Amazon specific request headers
	 *
	 * @var array
	 * @access private
	 */
	private $amzHeaders = array();

	/**
	 * HTTP request headers
	 *
	 * @var array
	 * @access private
	 */
	private $headers = array(
		'Host' => '', 'Date' => '', 'Content-MD5' => '', 'Content-Type' => ''
	);

	/**
	 * Use HTTP PUT?
	 *
	 * @var bool
	 * @access public
	 */
	public $fp = false;

	/**
	 * PUT file size
	 *
	 * @var int
	 * @access public
	 */
	public $size = 0;

	/**
	 * PUT post fields
	 *
	 * @var array
	 * @access public
	 */
	public $data = false;

	/**
	 * S3 request respone
	 *
	 * @var object
	 * @access public
	 */
	public $response;


	/**
	* Constructor
	*
	* @param string $verb Verb
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param string $endpoint AWS endpoint URI
	* @return mixed
	*/
	function __construct($verb, $bucket = '', $uri = '', $endpoint = 's3.amazonaws.com')
	{
		
		$this->endpoint = $endpoint;
		$this->verb = $verb;
		$this->bucket = $bucket;
		$this->uri = $uri !== '' ? '/'.str_replace('%2F', '/', rawurlencode($uri)) : '/';

		//if ($this->bucket !== '')
		//	$this->resource = '/'.$this->bucket.$this->uri;
		//else
		//	$this->resource = $this->uri;

		if ($this->bucket !== '')
		{
			if ($this->__dnsBucketName($this->bucket))
			{
				$this->headers['Host'] = $this->bucket.'.'.$this->endpoint;
				$this->resource = '/'.$this->bucket.$this->uri;
			}
			else
			{
				$this->headers['Host'] = $this->endpoint;
				$this->uri = $this->uri;
				if ($this->bucket !== '') $this->uri = '/'.$this->bucket.$this->uri;
				$this->bucket = '';
				$this->resource = $this->uri;
			}
		}
		else
		{
			$this->headers['Host'] = $this->endpoint;
			$this->resource = $this->uri;
		}


		$this->headers['Date'] = gmdate('D, d M Y H:i:s T');
		$this->response = new STDClass;
		$this->response->error = false;
		$this->response->body = null;
		$this->response->headers = array();
	}


	/**
	* Set request parameter
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setParameter($key, $value)
	{
		$this->parameters[$key] = $value;
	}


	/**
	* Set request header
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setHeader($key, $value)
	{
		$this->headers[$key] = $value;
	}


	/**
	* Set x-amz-meta-* header
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setAmzHeader($key, $value)
	{
		$this->amzHeaders[$key] = $value;
	}


	/**
	* Get the S3 response
	*
	* @return object | false
	*/
	public function getResponse()
	{
		$query = '';
		if (sizeof($this->parameters) > 0)
		{
			$query = substr($this->uri, -1) !== '?' ? '?' : '&';
			foreach ($this->parameters as $var => $value)
				if ($value == null || $value == '') $query .= $var.'&';
				else $query .= $var.'='.rawurlencode($value).'&';
			$query = substr($query, 0, -1);
			$this->uri .= $query;

			if (array_key_exists('acl', $this->parameters) ||
			array_key_exists('location', $this->parameters) ||
			array_key_exists('torrent', $this->parameters) ||
			array_key_exists('website', $this->parameters) ||
			array_key_exists('logging', $this->parameters))
				$this->resource .= $query;
		}
		$url = (S3::$useSSL ? 'https://' : 'http://') . ($this->headers['Host'] !== '' ? $this->headers['Host'] : $this->endpoint) . $this->uri;

		//var_dump('bucket: ' . $this->bucket, 'uri: ' . $this->uri, 'resource: ' . $this->resource, 'url: ' . $url);

		// Basic setup
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_USERAGENT, 'S3/php');

		if (S3::$useSSL)
		{
			// SSL Validation can now be optional for those with broken OpenSSL installations
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, S3::$useSSLValidation ? 2 : 0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, S3::$useSSLValidation ? 1 : 0);

			if (S3::$sslKey !== null) curl_setopt($curl, CURLOPT_SSLKEY, S3::$sslKey);
			if (S3::$sslCert !== null) curl_setopt($curl, CURLOPT_SSLCERT, S3::$sslCert);
			if (S3::$sslCACert !== null) curl_setopt($curl, CURLOPT_CAINFO, S3::$sslCACert);
		}

		curl_setopt($curl, CURLOPT_URL, $url);

		if (S3::$proxy != null && isset(S3::$proxy['host']))
		{
			curl_setopt($curl, CURLOPT_PROXY, S3::$proxy['host']);
			curl_setopt($curl, CURLOPT_PROXYTYPE, S3::$proxy['type']);
			if (isset(S3::$proxy['user'], S3::$proxy['pass']) && S3::$proxy['user'] != null && S3::$proxy['pass'] != null)
				curl_setopt($curl, CURLOPT_PROXYUSERPWD, sprintf('%s:%s', S3::$proxy['user'], S3::$proxy['pass']));
		}

		// Headers
		$headers = array(); $amz = array();
		foreach ($this->amzHeaders as $header => $value)
			if (strlen($value) > 0) $headers[] = $header.': '.$value;
		foreach ($this->headers as $header => $value)
			if (strlen($value) > 0) $headers[] = $header.': '.$value;

		// Collect AMZ headers for signature
		foreach ($this->amzHeaders as $header => $value)
			if (strlen($value) > 0) $amz[] = strtolower($header).':'.$value;

		// AMZ headers must be sorted
		if (sizeof($amz) > 0)
		{
			//sort($amz);
			usort($amz, array(&$this, '__sortMetaHeadersCmp'));
			$amz = "\n".implode("\n", $amz);
		} else $amz = '';

		if (S3::hasAuth())
		{
			// Authorization string (CloudFront stringToSign should only contain a date)
			if ($this->headers['Host'] == 'cloudfront.amazonaws.com')
				$headers[] = 'Authorization: ' . S3::__getSignature($this->headers['Date']);
			else
			{
				$headers[] = 'Authorization: ' . S3::__getSignature(
					$this->verb."\n".
					$this->headers['Content-MD5']."\n".
					$this->headers['Content-Type']."\n".
					$this->headers['Date'].$amz."\n".
					$this->resource
				);
			}
		}

		curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($curl, CURLOPT_HEADER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, false);
		curl_setopt($curl, CURLOPT_WRITEFUNCTION, array(&$this, '__responseWriteCallback'));
		curl_setopt($curl, CURLOPT_HEADERFUNCTION, array(&$this, '__responseHeaderCallback'));
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);

		// Request types
		switch ($this->verb)
		{
			case 'GET': break;
			case 'PUT': case 'POST': // POST only used for CloudFront
				if ($this->fp !== false)
				{
					curl_setopt($curl, CURLOPT_PUT, true);
					curl_setopt($curl, CURLOPT_INFILE, $this->fp);
					if ($this->size >= 0)
						curl_setopt($curl, CURLOPT_INFILESIZE, $this->size);
				}
				elseif ($this->data !== false)
				{
					curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $this->verb);
					curl_setopt($curl, CURLOPT_POSTFIELDS, $this->data);
				}
				else
					curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $this->verb);
			break;
			case 'HEAD':
				curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'HEAD');
				curl_setopt($curl, CURLOPT_NOBODY, true);
			break;
			case 'DELETE':
				curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
			break;
			default: break;
		}

		// Execute, grab errors
		if (curl_exec($curl))
			$this->response->code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		else
			$this->response->error = array(
				'code' => curl_errno($curl),
				'message' => curl_error($curl),
				'resource' => $this->resource
			);

		@curl_close($curl);

		// Parse body into XML
		if ($this->response->error === false && isset($this->response->headers['type']) &&
		$this->response->headers['type'] == 'application/xml' && isset($this->response->body))
		{
			$this->response->body = simplexml_load_string($this->response->body);

			// Grab S3 errors
			if (!in_array($this->response->code, array(200, 204, 206)) &&
			isset($this->response->body->Code, $this->response->body->Message))
			{
				$this->response->error = array(
					'code' => (string)$this->response->body->Code,
					'message' => (string)$this->response->body->Message
				);
				if (isset($this->response->body->Resource))
					$this->response->error['resource'] = (string)$this->response->body->Resource;
				unset($this->response->body);
			}
		}

		// Clean up file resources
		if ($this->fp !== false && is_resource($this->fp)) fclose($this->fp);

		return $this->response;
	}

	/**
	* Sort compare for meta headers
	*
	* @internal Used to sort x-amz meta headers
	* @param string $a String A
	* @param string $b String B
	* @return integer
	*/
	private function __sortMetaHeadersCmp($a, $b)
	{
		$lenA = strpos($a, ':');
		$lenB = strpos($b, ':');
		$minLen = min($lenA, $lenB);
		$ncmp = strncmp($a, $b, $minLen);
		if ($lenA == $lenB) return $ncmp;
		if (0 == $ncmp) return $lenA < $lenB ? -1 : 1;
		return $ncmp;
	}

	/**
	* CURL write callback
	*
	* @param resource &$curl CURL resource
	* @param string &$data Data
	* @return integer
	*/
	private function __responseWriteCallback(&$curl, &$data)
	{
		if (in_array($this->response->code, array(200, 206)) && $this->fp !== false)
			return fwrite($this->fp, $data);
		else
			$this->response->body .= $data;
		return strlen($data);
	}


	/**
	* Check DNS conformity
	*
	* @param string $bucket Bucket name
	* @return boolean
	*/
	private function __dnsBucketName($bucket)
	{
		if (strlen($bucket) > 63 || preg_match("/[^a-z0-9\.-]/", $bucket) > 0) return false;
		if (strstr($bucket, '-.') !== false) return false;
		if (strstr($bucket, '..') !== false) return false;
		if (!preg_match("/^[0-9a-z]/", $bucket)) return false;
		if (!preg_match("/[0-9a-z]$/", $bucket)) return false;
		return true;
	}


	/**
	* CURL header callback
	*
	* @param resource $curl CURL resource
	* @param string $data Data
	* @return integer
	*/
	private function __responseHeaderCallback($curl, $data)
	{
		if (($strlen = strlen($data)) <= 2) return $strlen;
		if (substr($data, 0, 4) == 'HTTP')
			$this->response->code = (int)substr($data, 9, 3);
		else
		{
			$data = trim($data);
			if (strpos($data, ': ') === false) return $strlen;
			list($header, $value) = explode(': ', $data, 2);
			if ($header == 'Last-Modified')
				$this->response->headers['time'] = strtotime($value);
			elseif ($header == 'Date')
				$this->response->headers['date'] = strtotime($value);
			elseif ($header == 'Content-Length')
				$this->response->headers['size'] = (int)$value;
			elseif ($header == 'Content-Type')
				$this->response->headers['type'] = $value;
			elseif ($header == 'ETag')
				$this->response->headers['hash'] = $value{0} == '"' ? substr($value, 1, -1) : $value;
			elseif (preg_match('/^x-amz-meta-.*$/', $header))
				$this->response->headers[$header] = $value;
		}
		return $strlen;
	}

}

/**
 * S3 exception class
 *
 * @link http://undesigned.org.za/2007/10/22/amazon-s3-php-class
 * @version 0.5.0-dev
 */

class S3Exception extends Exception {
	/**
	 * Class constructor
	 *
	 * @param string $message Exception message
	 * @param string $file File in which exception was created
	 * @param string $line Line number on which exception was created
	 * @param int $code Exception code
	 */
	function __construct($message, $file, $line, $code = 0)
	{
		parent::__construct($message, $code);
		$this->file = $file;
		$this->line = $line;
	}
}
