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

if (getenv('SIGNATURE_DEBUG') === 'ON') {
	function SigDebug($format)
	{
		$args = func_get_args();
		if (count($args) === 0) {
			return;
		}

		$args[0] .= "\n";
		array_unshift($args, STDERR);
		call_user_func_array('fprintf', $args);
	}
} else {
	function SigDebug()
	{}
}


/**
* Amazon S3 PHP class
*
* @link http://undesigned.org.za/2007/10/22/amazon-s3-php-class
* @version 0.5.1
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
	const STORAGE_CLASS_STANDARD_IA = 'STANDARD_IA';

	const SSE_NONE = '';
	const SSE_AES256 = 'AES256';

	const SigV2 = 'sigv2';
	const SigV4 = 'sigv4';

	/**
	 * Default credentials to access AWS
	 *
	 * @var S3Credentials|null
	 */
	private static $__defaultCredentials;

	/**
	 * Default endpoint
	 *
	 * @var S3EndpointConfig|null
	 */
	private static $__defaultEndpoint;

	/**
	 * Default delimiter to be used, for example while getBucket().
	 * @var string|null
	 * @access public
	 * @static 
	 */
	public static $defDelimiter;

	/**
	 * AWS Region
	 *
	 * @var string
	 * @acess public
	 * @static
	 */
	public static $region = '';

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
	 * AWS Key Pair ID
	 *
	 * @var string|null
	 * @access private
	 * @static
	 */
	private static $__signingKeyPairId;
	
	/**
	 * Key resource, freeSigningKey() must be called to clear it from memory
	 *
	 * @var resource|bool
	 * @access private
	 * @static 
	 */
	private static $__signingKeyResource = false;

	/**
	 * CURL progress function callback 
	 *
	 * @var callable|null
	 * @access public
	 * @static 
	 */
	public static $progressFunction;

	/**
	 * Constructor
	 *
	 * @param string $accessKey Access key
	 * @param string $secretKey Secret key
	 * @param boolean $useSSL Enable SSL
	 * @param string $endpoint Amazon URI
	 * @param string $region AWS auth region for SigV4
	 *
	 * @deprecated Use static initializer S3::Init() instead
	 */
	public function __construct($accessKey = null, $secretKey = null, $useSSL = false, $endpoint = 's3.amazonaws.com', $region = '')
	{
		$creds = null;
		if ($accessKey !== null && $secretKey !== null)
		{
			$creds = new S3Credentials($accessKey, $secretKey);
		}

		$endpointCfg = new S3EndpointConfig($endpoint);
		$endpointCfg->withSSLEnabled($useSSL);

		self::Init($creds, $region, $endpointCfg);
	}

	/**
	 * Initialise default parameters
	 *
	 * @param S3Credentials $credentials Default credentials
	 * @param string $region Auth region for SigV4
	 * @param S3EndpointConfig|null $endpoint Endpoint configuration, null for AWS S3 settings
	 */
	public static function Init(S3Credentials $credentials, $region = '', S3EndpointConfig $endpoint = null)
	{
		self::setCredentials($credentials);

		self::$region = $region;

		if ($endpoint === null) {
			$endpoint = new S3EndpointConfig();
		}

		self::setEndpoint($endpoint);
	}

	/**
	 * Endpoint override helper
	 *
	 * @param S3EndpointConfig|null $endpoint
	 * @return S3EndpointConfig
	 */
	public static function getEndpoint(S3EndpointConfig $endpoint = null)
	{
		if ($endpoint !== null) {
			return $endpoint;
		}

		if (self::$__defaultEndpoint === null) {
			self::$__defaultEndpoint = new S3EndpointConfig();
		}

		return self::$__defaultEndpoint;
	}


	/**
	 * Set the service endpoint
	 *
	 * @param S3EndpointConfig $endpoint
	 * @return void
	 */
	public static function setEndpoint(S3EndpointConfig $endpoint)
	{
		self::$__defaultEndpoint = $endpoint;
	}


	/**
	* Set the service region
	*
	* @param string $region
	* @return void
	*/
	public function setRegion($region)
	{
		self::$region = $region;
	}


	/**
	 * Get the service region
	 *
	 * @param S3EndpointConfig|null $endpoint
	 * @return string
	 * @static
	 */
	public static function getRegion(S3EndpointConfig $endpoint = null)
	{
		if (!empty(self::$region))
		{
			return self::$region;
		}

		// deduce region from default endpoint
		return self::getEndpoint($endpoint)
			->getRegion();
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
		self::setCredentials(new S3Credentials($accessKey, $secretKey));
	}


	/**
	 * Set default credentials
	 *
	 * @param S3Credentials $creds
	 */
	public static function setCredentials(S3Credentials $creds)
	{
		self::$__defaultCredentials = $creds;
	}


	/**
	* Check if AWS keys have been set
	*
	* @return boolean
	*/
	public static function hasAuth() {
		return self::$__defaultCredentials !== null && self::$__defaultCredentials->isInitialised();
	}


	/**
	 * Get access-key if set, otherwise null
	 *
	 * @param S3Credentials|null $creds
	 * @return S3Credentials|null
	 */
	public static function getCredentials(S3Credentials $creds = null)
	{
		if ($creds !== null && $creds->isInitialised()) {
			return $creds;
		}

		if (self::hasAuth()) {
			return self::$__defaultCredentials;
		}

		return null;
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
		self::getEndpoint()
			->withSSLEnabled($enabled)
			->withSSLValidationEnabled($validate);
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
		self::getEndpoint()
			->withSSLEnabled()
			->withSSLValidationEnabled()
			->withSSLAuth($sslCert, $sslKey, $sslCACert);
	}


	/**
	* Set proxy information
	*
	* @param string $host Proxy hostname and port (localhost:1234)
	* @param string $user Proxy username
	* @param string $pass Proxy password
	* @param int $type CURL proxy type (constants defined in curl module)
	* @return void
	*/
	public static function setProxy($host, $user = null, $pass = null, $type = CURLPROXY_SOCKS5)
	{
		self::getEndpoint()
			->withProxy($host, $user, $pass, $type);
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
	 * @param int $offset Time offset (set to zero to use AWS server time)
	 * @param S3EndpointConfig|null $endpoint
	 * @return void
	 */
	public static function setTimeCorrectionOffset($offset = 0, S3EndpointConfig $endpoint = null)
	{
		if ($offset === 0)
		{
			$rest = new S3Request('HEAD', null, '', $endpoint);
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

		if ($isFile)
		{
			$signingKeyMaterial = file_get_contents($signingKey);
		}
		else
		{
			$signingKeyMaterial = $signingKey;
		}

		if ($signingKeyMaterial !== false)
		{
			self::$__signingKeyResource = openssl_pkey_get_private($signingKeyMaterial);
		}

		if ($signingKeyMaterial === false || self::$__signingKeyResource === false)
		{
			self::__triggerError('S3::setSigningKey(): Unable to open load private key: ' . $signingKey, __FILE__, __LINE__);
			return false;
		}

		return true;
	}



	/**
	* Free signing key from memory, MUST be called if you are using setSigningKey()
	*
	* @return void
	*/
	public static function freeSigningKey()
	{
		if (self::$__signingKeyResource !== false)
		{
			openssl_free_key(self::$__signingKeyResource);
		}
	}

	/**
	* Set progress function
	*
	* @param callable $func Progress function
	* @return void
	*/
	public static function setProgressFunction($func = null)
	{
		self::$progressFunction = $func;
	}


	/**
	 * Internal error handler
	 *
	 * @param string $message Error message
	 * @param string $file Filename
	 * @param integer $line Line number
	 * @param integer $code Error code
	 * @return void
	 * @internal Internal error handler
	 *
	 * @throws null
	 */
	private static function __triggerError($message, $file, $line, $code = 0)
	{
		if (self::$useExceptions)
		{
			throw new S3Exception($message, $file, $line, $code);
		}

		trigger_error($message, E_USER_WARNING);
	}


	/**
	 * Get a list of buckets
	 *
	 * @param boolean $detailed Returns detailed bucket list when true
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function listBuckets($detailed = false, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('GET', null, '', $endpoint, $creds);
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $prefix Prefix
	 * @param string $marker Marker (last file listed)
	 * @param string $maxKeys Max keys (maximum number of keys to return)
	 * @param string $delimiter Delimiter
	 * @param boolean $returnCommonPrefixes Set to true to return CommonPrefixes
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function getBucket($bucket, $prefix = null, $marker = null, $maxKeys = null, $delimiter = null,
									 $returnCommonPrefixes = false,
									 S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('GET', $bucket, '', $endpoint, $creds);
		if ($maxKeys === 0) $maxKeys = null;
		if ($prefix !== null && $prefix !== '') $rest->setParameter('prefix', $prefix);
		if ($marker !== null && $marker !== '') $rest->setParameter('marker', $marker);
		if ($maxKeys !== null && $maxKeys !== '') $rest->setParameter('max-keys', $maxKeys);
		if ($delimiter !== null && $delimiter !== '') $rest->setParameter('delimiter', $delimiter);
		else if (!empty(self::$defDelimiter)) $rest->setParameter('delimiter', self::$defDelimiter);
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
		(string)$response->body->IsTruncated === 'false') return $results;

		if (isset($response->body, $response->body->NextMarker))
			$nextMarker = (string)$response->body->NextMarker;

		// Loop through truncated results if maxKeys isn't specified
		if ($maxKeys === null && $nextMarker !== null && (string)$response->body->IsTruncated === 'true')
		do
		{
			$rest = new S3Request('GET', $bucket, '', $endpoint, $creds);
			if ($prefix !== null && $prefix !== '') $rest->setParameter('prefix', $prefix);
			$rest->setParameter('marker', $nextMarker);
			if ($delimiter !== null && $delimiter !== '') $rest->setParameter('delimiter', $delimiter);

			if (($response = $rest->getResponse()) === false || $response->code !== 200) break;

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

		} while ($response !== false && (string)$response->body->IsTruncated === 'true');

		return $results;
	}


	/**
	 * Put a bucket
	 *
	 * @param string $bucket Bucket name
	 * @param string $acl ACL flag
	 * @param string|bool $location Set as "EU" to create buckets hosted in Europe
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function putBucket($bucket, $acl = self::ACL_PRIVATE, $location = false, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$endpoint = self::getEndpoint($endpoint);

		if ($location === false)
		{
			$location = self::getRegion($endpoint);
			if (empty($location))
			{
				self::__triggerError("S3::putBucket({$bucket}, {$acl}, {$location}): Could not deduce region-code", __FILE__, __LINE__);
				return false;
			}
		}

		$rest = new S3Request('PUT', new S3BucketConfig($bucket, $endpoint->defaultRegion), '', $endpoint, $creds);
		$rest->setAmzHeader('x-amz-acl', $acl);

		if ($endpoint->hostname !== S3EndpointConfig::AWS_S3_DEFAULT_HOST
			|| $location !== S3EndpointConfig::AWS_S3_DEFAULT_REGION) {

			$dom = new DOMDocument;
			$createBucketConfiguration = $dom->createElement('CreateBucketConfiguration');
			$locationConstraint = $dom->createElement('LocationConstraint', $location);
			$createBucketConfiguration->appendChild($locationConstraint);
			$dom->appendChild($createBucketConfiguration);

			$rest->data = $dom->saveXML();
			$rest->size = strlen($rest->data);
			$rest->setHeader('Content-Type', 'application/xml');
		} else {
			$rest->data = '';
			$rest->size = 0;
		}

		$rest = $rest->getResponse();

		if ($rest->error === false && $rest->code !== 200)
		{
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		}

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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function deleteBucket($bucket, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('DELETE', $bucket, '', $endpoint, $creds);
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
		clearstatcache(false, $file);

		if ($md5sum === false) {
			$md5sum = '';
		} elseif (!is_string($md5sum)) {
			$md5sum = base64_encode(md5_file($file, true));
		}

		return array(
			'file' => $file,
			'size' => filesize($file),
			'md5sum' => $md5sum,
			'sha256sum' => hash_file('sha256', $file)
		);
	}


	/**
	 * Create input array info for putObject() with a resource
	 *
	 * @param resource $resource Input resource to read from
	 * @param int|bool $bufferSize Input byte size
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param string $acl ACL constant
	 * @param array $metaHeaders Array of x-amz-meta-* headers
	 * @param array|string $requestHeaders Array of request headers or content type as a string
	 * @param string $storageClass Storage class constant
	 * @param string $serverSideEncryption Server-side encryption
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function putObject($input, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $requestHeaders = array(), $storageClass = self::STORAGE_CLASS_STANDARD, $serverSideEncryption = self::SSE_NONE, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		if ($input === false) return false;
		$rest = new S3Request('PUT', $bucket, $uri, $endpoint, $creds);

		if (!is_array($input)) $input = array(
			'data' => $input, 'size' => strlen($input),
			'md5sum' => base64_encode(md5($input, true)),
			'sha256sum' => hash('sha256', $input)
		);

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
		else if (isset($input['file'])) {
			clearstatcache(false, $input['file']);
			$rest->size = filesize($input['file']);
		}
		elseif (isset($input['data']))
			$rest->size = strlen($input['data']);

		// Custom request headers (Content-Type, Content-Disposition, Content-Encoding)
		if (is_array($requestHeaders))
			foreach ($requestHeaders as $h => $v)
				strpos($h, 'x-amz-') === 0 ? $rest->setAmzHeader($h, $v) : $rest->setHeader($h, $v);
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

			if (isset($input['sha256sum'])) $rest->setAmzHeader('x-amz-content-sha256', $input['sha256sum']);

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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param string $acl ACL constant
	 * @param array $metaHeaders Array of x-amz-meta-* headers
	 * @param string $contentType Content type
	 * @param string $storageClass
	 * @param string $serverSideEncryption
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function putObjectFile(
		$file, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = null,
		$storageClass = self::STORAGE_CLASS_STANDARD, $serverSideEncryption = self::SSE_NONE,
		S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		return self::putObject(self::inputFile($file), $bucket, $uri, $acl, $metaHeaders, $contentType, $storageClass, $serverSideEncryption, $endpoint, $creds);
	}


	/**
	 * Put an object from a string (legacy function)
	 *
	 * @param string $string Input data
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param string $acl ACL constant
	 * @param array $metaHeaders Array of x-amz-meta-* headers
	 * @param string $contentType Content type
	 * @param string $storageClass
	 * @param string $serverSideEncryption
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function putObjectString(
		$string, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = 'text/plain',
		$storageClass = self::STORAGE_CLASS_STANDARD, $serverSideEncryption = self::SSE_NONE,
		S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		return self::putObject($string, $bucket, $uri, $acl, $metaHeaders, $contentType, $storageClass, $serverSideEncryption, $endpoint, $creds);
	}


	/**
	 * Get an object
	 *
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param mixed $saveTo Filename or resource to write to
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return mixed
	 */
	public static function getObject($bucket, $uri, $saveTo = false, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('GET', $bucket, $uri, $endpoint, $creds);
		if ($saveTo !== false)
		{
			if (is_resource($saveTo))
				$rest->fp =& $saveTo;
			else if (($rest->fp = @fopen($saveTo, 'wb')) === false)
				$rest->response->error = array('code' => 0, 'message' => 'Unable to open save file for writing: ' . $saveTo);
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param boolean $returnInfo Return response information
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return mixed | false
	 */
	public static function getObjectInfo($bucket, $uri, $returnInfo = true, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('HEAD', $bucket, $uri, $endpoint, $creds);
		$rest = $rest->getResponse();
		if ($rest->error === false && ($rest->code !== 200 && $rest->code !== 404))
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getObjectInfo({$bucket}, {$uri}): [%s] %s",
				$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}

		if ($rest->code !== 200)
		{
			return false;
		}

		return $returnInfo ? $rest->headers : true;
	}


	/**
	 * Copy an object
	 *
	 * @param string $srcBucket Source bucket name
	 * @param string $srcUri Source object URI
	 * @param string|S3BucketConfig $bucket Destination bucket name
	 * @param string $uri Destination object URI
	 * @param string $acl ACL constant
	 * @param array $metaHeaders Optional array of x-amz-meta-* headers
	 * @param array $requestHeaders Optional array of request headers (content type, disposition, etc.)
	 * @param string $storageClass Storage class constant
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return mixed | false
	 */
	public static function copyObject($srcBucket, $srcUri, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $requestHeaders = array(), $storageClass = self::STORAGE_CLASS_STANDARD, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('PUT', $bucket, $uri, $endpoint, $creds);
		$rest->setHeader('Content-Length', 0);
		foreach ($requestHeaders as $h => $v)
				strpos($h, 'x-amz-') === 0 ? $rest->setAmzHeader($h, $v) : $rest->setHeader($h, $v);
		foreach ($metaHeaders as $h => $v) $rest->setAmzHeader('x-amz-meta-'.$h, $v);
		if ($storageClass !== self::STORAGE_CLASS_STANDARD) // Storage class
			$rest->setAmzHeader('x-amz-storage-class', $storageClass);
		$rest->setAmzHeader('x-amz-acl', $acl);
		$rest->setAmzHeader('x-amz-copy-source', sprintf('/%s/%s', $srcBucket, rawurlencode($srcUri)));
		if (count($requestHeaders) > 0 || count($metaHeaders) > 0)
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $location Target host name
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function setBucketRedirect($bucket = NULL, $location = NULL, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('PUT', $bucket, '', $endpoint, $creds);

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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $targetBucket Target bucket (where logs are stored)
	 * @param string $targetPrefix Log prefix (e,g; domain.com-)
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function setBucketLogging($bucket, $targetBucket, $targetPrefix = null, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		// The S3 log delivery group has to be added to the target bucket's ACP
		if ($targetBucket !== null && ($acp = self::getAccessControlPolicy($targetBucket)) !== false)
		{
			// Only add permissions to the target bucket when they do not exist
			$aclWriteSet = false;
			$aclReadSet = false;
			foreach ($acp['acl'] as $acl)
			if ($acl['type'] === 'Group' && $acl['uri'] === 'http://acs.amazonaws.com/groups/s3/LogDelivery')
			{
				if ($acl['permission'] === 'WRITE') $aclWriteSet = true;
				elseif ($acl['permission'] === 'READ_ACP') $aclReadSet = true;
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
			if ($targetPrefix === null) $targetPrefix = $bucket . '-';
			$loggingEnabled = $dom->createElement('LoggingEnabled');
			$loggingEnabled->appendChild($dom->createElement('TargetBucket', $targetBucket));
			$loggingEnabled->appendChild($dom->createElement('TargetPrefix', $targetPrefix));
			// TODO: Add TargetGrants?
			$bucketLoggingStatus->appendChild($loggingEnabled);
		}
		$dom->appendChild($bucketLoggingStatus);

		$rest = new S3Request('PUT', $bucket, '', $endpoint, $creds);
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function getBucketLogging($bucket, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('GET', $bucket, '', $endpoint, $creds);
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function disableBucketLogging($bucket, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		return self::setBucketLogging($bucket, null, null, $endpoint, $creds);
	}


	/**
	 * Get a bucket's location
	 *
	 * @param string $bucket Bucket name
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return string | false
	 */
	public static function getBucketLocation($bucket, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		// https://github.com/aws/aws-sdk-js/issues/462
		// Setting up any region other than 'us-east-1'
		$bucketConfig = new S3BucketConfig($bucket, 'us-west-2');

		$rest = new S3Request('GET', $bucketConfig, '', $endpoint, $creds);
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
	 * @param string|S3BucketConfig $bucket Bucket name
	 * @param string $uri Object URI
	 * @param array $acp Access Control Policy Data (same as the data returned from getAccessControlPolicy)
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function setAccessControlPolicy($bucket, $uri = '', $acp = array(), S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
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
			elseif ($g['type'] === 'Group')
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

		$rest = new S3Request('PUT', $bucket, $uri, $endpoint, $creds);
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
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return mixed | false
	 */
	public static function getAccessControlPolicy($bucket, $uri = '', S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('GET', $bucket, $uri, $endpoint, $creds);
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
	 * @param S3EndpointConfig|null $endpoint
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function deleteObject($bucket, $uri, S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$rest = new S3Request('DELETE', $bucket, $uri, $endpoint, $creds);
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
	 * @return string|false
	 */
	public static function getAuthenticatedURL($bucket, $uri, $lifetime, $hostBucket = false, $https = false)
	{
		$creds = self::getCredentials();
		if ($creds === null) {
			self::__triggerError("S3::getAuthenticatedURL({$bucket}, {$uri}, ...): No credentials set", __FILE__, __LINE__);
			return false;
		}

		$expires = self::__getTime() + $lifetime;
		$uri = str_replace(array('%2F', '%2B'), array('/', '+'), rawurlencode($uri));
		return sprintf(($https ? 'https' : 'http') . '://%s/%s?AWSAccessKeyId=%s&Expires=%u&Signature=%s',
			// $hostBucket ? $bucket : $bucket.'.s3.amazonaws.com', $uri, self::$__accessKey, $expires,
			$hostBucket ? $bucket : self::getEndpoint()->hostname . '/' . $bucket, $uri, $creds->accessKey, $expires,
			urlencode(self::__getHash("GET\n\n\n{$expires}\n/{$bucket}/{$uri}", $creds->secretKey)));
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
	* @param string $acl ACL constant
	* @param integer $lifetime Lifetime in seconds
	* @param integer $maxFileSize Maximum filesize in bytes (default 5MB)
	* @param string $successRedirect Redirect URL or 200 / 201 status code
	* @param array $amzHeaders Array of x-amz-meta-* headers
	* @param array $headers Array of request headers or content type as a string
	* @param boolean $flashVars Includes additional "Filename" variable posted by Flash
	* @return object|false
	*/
	public static function getHttpUploadPostParams(
		$bucket, $uriPrefix = '', $acl = self::ACL_PRIVATE, $lifetime = 3600, $maxFileSize = 5242880,
		$successRedirect = "201", $amzHeaders = array(), $headers = array(), $flashVars = false)
	{
		$creds = self::getCredentials();
		if ($creds === null) {
			self::__triggerError("S3::getHttpUploadPostParams({$bucket}, ...): No credentials set", __FILE__, __LINE__);
			return false;
		}

		// Create policy object
		$policy = new stdClass;
		$policy->expiration = gmdate('Y-m-d\TH:i:s\Z', (self::__getTime() + $lifetime));
		$policy->conditions = array();
		$obj = new stdClass; $obj->bucket = $bucket; $policy->conditions[] = $obj;
		$obj = new stdClass; $obj->acl = $acl; $policy->conditions[] = $obj;

		$obj = new stdClass; // 200 for non-redirect uploads
		if (is_numeric($successRedirect) && in_array((int)$successRedirect, array(200, 201), true))
			$obj->success_action_status = (string)$successRedirect;
		else // URL
			$obj->success_action_redirect = $successRedirect;
		$policy->conditions[] = $obj;

		if ($acl !== self::ACL_PUBLIC_READ)
			$policy->conditions[] = array('eq', '$acl', $acl);

		$policy->conditions[] = array('starts-with', '$key', $uriPrefix);
		if ($flashVars) $policy->conditions[] = array('starts-with', '$Filename', '');
		foreach (array_keys($headers) as $headerKey)
			$policy->conditions[] = array('starts-with', '$' . $headerKey, '');
		foreach ($amzHeaders as $headerKey => $headerVal)
		{
			$obj = new stdClass;
			$obj->{$headerKey} = (string)$headerVal;
			$policy->conditions[] = $obj;
		}
		$policy->conditions[] = array('content-length-range', 0, $maxFileSize);
		$policy = base64_encode(str_replace('\/', '/', json_encode($policy)));

		// Create parameters
		$params = new stdClass;
		$params->AWSAccessKeyId = $creds->accessKey;
		$params->key = $uriPrefix.'${filename}';
		$params->acl = $acl;
		$params->policy = $policy; unset($policy);
		$params->signature = self::__getHash($params->policy, $creds);
		if (is_numeric($successRedirect) && in_array((int)$successRedirect, array(200, 201), true))
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
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function createDistribution($bucket, $enabled = true, $cnames = array(), $comment = null, $defaultRootObject = null, $originAccessIdentity = null, $trustedSigners = array(), S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::createDistribution({$bucket}, " . (int)$enabled . ", [], '$comment'): %s",
				"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('POST', null, '2010-11-01/distribution', $cloudfrontEndpoint, $creds);
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

		if ($rest->error === false && $rest->code !== 201)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::createDistribution({$bucket}, " . (int)$enabled . ", [], '$comment'): [%s] %s",
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
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function getDistribution($distributionId, S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::getDistribution($distributionId): %s",
				"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('GET', null, '2010-11-01/distribution/'.$distributionId, $cloudfrontEndpoint, $creds);
		$rest = self::__getCloudFrontResponse($rest);

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::getDistribution($distributionId): [%s] %s",
				$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}

		if ($rest->body instanceof SimpleXMLElement)
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
	 * @param S3Credentials|null $creds
	 * @return array | false
	 */
	public static function updateDistribution($dist, S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::updateDistribution({$dist['id']}): %s",
				"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('PUT', null, '2010-11-01/distribution/'.$dist['id'].'/config', $cloudfrontEndpoint, $creds);
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

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf("S3::updateDistribution({$dist['id']}): [%s] %s",
				$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}

		$dist = self::__parseCloudFrontDistributionConfig($rest->body);
		$dist['hash'] = $rest->headers['hash'];
		return $dist;
	}


	/**
	 * Delete a CloudFront distribution
	 *
	 * @param array $dist Distribution array info identical to output of getDistribution()
	 * @param S3Credentials|null $creds
	 * @return boolean
	 */
	public static function deleteDistribution($dist, S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError(sprintf("S3::deleteDistribution({$dist['id']}): %s",
				"CloudFront functionality requires SSL"), __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('DELETE', null, '2008-06-30/distribution/'.$dist['id'], $cloudfrontEndpoint, $creds);
		$rest->setHeader('If-Match', $dist['hash']);
		$rest = self::__getCloudFrontResponse($rest);

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
	 * @param S3Credentials|null $creds
	 * @return array|bool
	 */
	public static function listDistributions(S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError('S3::listDistributions(): CloudFront functionality requires SSL', __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('GET', null, '2010-11-01/distribution', $cloudfrontEndpoint, $creds);
		$rest = self::__getCloudFrontResponse($rest);

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			self::__triggerError(sprintf('S3::listDistributions(): [%s] %s',
				$rest->error['code'], $rest->error['message']), __FILE__, __LINE__);
			return false;
		}

		if ($rest->body instanceof SimpleXMLElement && isset($rest->body->DistributionSummary))
		{
			$list = array();
			foreach ($rest->body->DistributionSummary as $summary)
				$list[(string)$summary->Id] = self::__parseCloudFrontDistributionConfig($summary);

			return $list;
		}
		return array();
	}

	/**
	 * List CloudFront Origin Access Identities
	 *
	 * @param S3Credentials|null $creds
	 * @return array|bool
	 */
	public static function listOriginAccessIdentities(S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError('S3::listOriginAccessIdentities(): CloudFront functionality requires SSL', __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');
		$rest = new S3Request('GET', null, '2010-11-01/origin-access-identity/cloudfront', $cloudfrontEndpoint, $creds);
		$rest = self::__getCloudFrontResponse($rest);

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
	 * @param S3Credentials|null $creds
	 * @return bool
	 */
	public static function invalidateDistribution($distributionId, $paths, S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError('S3::invalidateDistribution(): CloudFront functionality requires SSL', __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');

		$rest = new S3Request('POST', null, '2010-08-01/distribution/'.$distributionId.'/invalidation', $cloudfrontEndpoint, $creds);
		$rest->data = self::__getCloudFrontInvalidationBatchXML($paths, (string)microtime(true));
		$rest->size = strlen($rest->data);
		$rest = self::__getCloudFrontResponse($rest);

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
	 * @param array $paths Paths to objects to invalidateDistribution
	 * @param string $callerReference
	 * @return string
	 * @internal Used to create XML in invalidateDistribution()
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
	 *    Array
	 *    (
	 *        [I31TWB0CN9V6XD] => InProgress
	 *        [IT3TFE31M0IHZ] => Completed
	 *        [I12HK7MPO1UQDA] => Completed
	 *        [I1IA7R6JKTC3L2] => Completed
	 *    )
	 *
	 * @param string $distributionId Distribution ID from listDistributions()
	 * @param S3Credentials|null $creds
	 * @return array|bool
	 */
	public static function getDistributionInvalidationList($distributionId, S3Credentials $creds = null)
	{
		if (!extension_loaded('openssl'))
		{
			self::__triggerError('S3::getDistributionInvalidationList(): CloudFront functionality requires SSL', __FILE__, __LINE__);
			return false;
		}

		$cloudfrontEndpoint = new S3EndpointConfig('cloudfront.amazonaws.com');

		$rest = new S3Request('GET', null, '2010-11-01/distribution/'.$distributionId.'/invalidation', $cloudfrontEndpoint, $creds);
		$rest = self::__getCloudFrontResponse($rest);

		if ($rest->error === false && $rest->code !== 200)
			$rest->error = array('code' => $rest->code, 'message' => 'Unexpected HTTP status');
		if ($rest->error !== false)
		{
			trigger_error(sprintf("S3::getDistributionInvalidationList('{$distributionId}'): [%s]: %s",
				$rest->error['code'], $rest->error['message']), E_USER_WARNING);
			return false;
		}

		if ($rest->body instanceof SimpleXMLElement && isset($rest->body->InvalidationSummary))
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

		if (!empty($trustedSigners))
		{
			$trusted = $dom->createElement('TrustedSigners');
			foreach ($trustedSigners as $id => $type)
				$trusted->appendChild($id !== '' ? $dom->createElement($type, $id) : $dom->createElement($type));
			$distributionConfig->appendChild($trusted);
		}
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
			$dist['enabled'] = (string)$node->Enabled === 'true';

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
		is_string($rest->response->body) && strpos($rest->response->body, '<?xml') === 0)
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
		static $exts = array(
			'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif',
			'png' => 'image/png', 'ico' => 'image/x-icon', 'pdf' => 'application/pdf',
			'tif' => 'image/tiff', 'tiff' => 'image/tiff', 'svg' => 'image/svg+xml',
			'svgz' => 'image/svg+xml', 'swf' => 'application/x-shockwave-flash', 
			'zip' => 'application/zip', 'gz' => 'application/x-gzip',
			'tar' => 'application/x-tar', 'bz' => 'application/x-bzip',
			'bz2' => 'application/x-bzip2',  'rar' => 'application/x-rar-compressed',
			'exe' => 'application/x-msdownload', 'msi' => 'application/x-msdownload',
			'cab' => 'application/vnd.ms-cab-compressed', 'txt' => 'text/plain',
			'asc' => 'text/plain', 'htm' => 'text/html', 'html' => 'text/html',
			'css' => 'text/css', 'js' => 'text/javascript',
			'xml' => 'text/xml', 'xsl' => 'application/xsl+xml',
			'ogg' => 'application/ogg', 'mp3' => 'audio/mpeg', 'wav' => 'audio/x-wav',
			'avi' => 'video/x-msvideo', 'mpg' => 'video/mpeg', 'mpeg' => 'video/mpeg',
			'mov' => 'video/quicktime', 'flv' => 'video/x-flv', 'php' => 'text/x-php'
		);

		$ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
		if (isset($exts[$ext])) return $exts[$ext];

		// Use fileinfo if available
		if (isset($_ENV['MAGIC']) && extension_loaded('fileinfo') &&
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
			if ($type !== false && $type !== '') return $type;
		}

		return 'application/octet-stream';
	}


	/**
	* Get the current time
	*
	* @internal Used to apply offsets to system time
	* @return integer
	*/
	public static function __getTime()
	{
		return time() + self::$__timeOffset;
	}


	/**
	 * Generate the auth string: "AWS AccessKey:Signature"
	 *
	 * @param string $string String to sign
	 * @param S3Credentials $creds
	 * @return string
	 * @internal Used by S3Request::getResponse()
	 */
	public static function __getSignature($string, S3Credentials $creds)
	{
		return 'AWS '.$creds->accessKey.':'.self::__getHash($string, $creds->secretKey);
	}


	/**
	 * Creates a HMAC-SHA1 hash
	 *
	 * This uses the hash extension if loaded
	 *
	 * @param string $string String to sign
	 * @param string $secretKey
	 * @return string
	 * @internal Used by __getSignature()
	 */
	private static function __getHash($string, $secretKey)
	{
		if (extension_loaded('hash')) {
			return base64_encode(
				hash_hmac('sha1', $string, $secretKey, true));
		}

		return base64_encode(
			pack('H*', sha1(
				(str_pad($secretKey, 64, chr(0x00)) ^ str_repeat(chr(0x5c), 64)) .
				pack('H*', sha1(
					(str_pad($secretKey, 64, chr(0x00)) ^ str_repeat(chr(0x36), 64)) . $string)))));
	}


	/**
	 * Generate the headers for AWS Signature V4
	 *
	 * @param array $amzHeaders
	 * @param array $headers
	 * @param string $method
	 * @param string $uri
	 * @param array $parameters
	 * @param S3Credentials $creds
	 * @param string $region
	 * @return string
	 * @internal Used by S3Request::getResponse()
	 */
	public static function __getSignatureV4($amzHeaders, $headers, $method, $uri, $parameters, S3Credentials $creds, $region)
	{
		$service = 's3';

		$algorithm = 'AWS4-HMAC-SHA256';
		$combinedHeaders = array();

		$amzDateStamp = substr($amzHeaders['x-amz-date'], 0, 8);

		// CanonicalHeaders
		foreach ($headers as $k => $v)
			$combinedHeaders[strtolower($k)] = trim($v);
		foreach ($amzHeaders as $k => $v) 
			$combinedHeaders[strtolower($k)] = trim($v);
		uksort($combinedHeaders, array('self', '__sortMetaHeadersCmp'));

		// Convert null query string parameters to strings and sort
		$parameters = array_map('strval', $parameters); 
		uksort($parameters, array('self', '__sortMetaHeadersCmp'));
		$queryString = http_build_query($parameters, null, '&', PHP_QUERY_RFC3986);

		// Payload
		$amzPayload = array($method);

		$qsPos = strpos($uri, '?');
		$amzPayload[] = ($qsPos === false ? $uri : substr($uri, 0, $qsPos));

		$amzPayload[] = $queryString;
		// add header as string to requests
		foreach ($combinedHeaders as $k => $v ) 
		{
			$amzPayload[] = $k . ':' . $v;
		}
		// add a blank entry so we end up with an extra line break
		$amzPayload[] = '';
		// SignedHeaders
		$amzPayload[] = implode(';', array_keys($combinedHeaders));
		// payload hash
		$amzPayload[] = $amzHeaders['x-amz-content-sha256'];
		// request as string
		$amzPayloadStr = implode("\n", $amzPayload);

		SigDebug('Payload to sign: [%s]', $amzPayloadStr);

		// CredentialScope
		$credentialScope = array($amzDateStamp, $region, $service, 'aws4_request');

		// stringToSign
		$stringToSignStr = implode("\n", array($algorithm, $amzHeaders['x-amz-date'],
			implode('/', $credentialScope), hash('sha256', $amzPayloadStr)));

		SigDebug('String to sign: [%s]', $stringToSignStr);

		// Make Signature
		$kSecret = 'AWS4' . $creds->secretKey;
		SigDebug('$kSecret: %s', crc32($kSecret));
		$kDate = hash_hmac('sha256', $amzDateStamp, $kSecret, true);
		SigDebug('$kDate: %s', crc32($kDate));
		$kRegion = hash_hmac('sha256', $region, $kDate, true);
		SigDebug('$kRegion: %s', crc32($kRegion));
		$kService = hash_hmac('sha256', $service, $kRegion, true);
		SigDebug('$kService: %s', crc32($kService));
		$kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
		SigDebug('$kSigning: %s', crc32($kSigning));

		$signature = hash_hmac('sha256', $stringToSignStr, $kSigning);

		return $algorithm . ' ' . implode(',', array(
			'Credential=' . $creds->accessKey . '/' . implode('/', $credentialScope),
			'SignedHeaders=' . implode(';', array_keys($combinedHeaders)),
			'Signature=' . $signature,
		));
	}


	/**
	* Sort compare for meta headers
	*
	* @internal Used to sort x-amz meta headers
	* @param string $a String A
	* @param string $b String B
	* @return integer
	*/
	private static function __sortMetaHeadersCmp($a, $b)
	{
		$lenA = strlen($a);
		$lenB = strlen($b);
		$minLen = min($lenA, $lenB);
		$ncmp = strncmp($a, $b, $minLen);
		if ($lenA === $lenB) return $ncmp;
		if (0 === $ncmp) return $lenA < $lenB ? -1 : 1;
		return $ncmp;
	}


	/**
	 * Helper to transition from bucket names to bucket-config
	 *
	 * @param string|S3BucketConfig $bucket
	 * @param S3EndpointConfig $endpoint
	 * @return S3BucketConfig
	 */
	public static function makeBucketConfig($bucket, S3EndpointConfig $endpoint)
	{
		if ($bucket instanceof S3BucketConfig) {
			return $bucket;
		}

		return new S3BucketConfig($bucket, self::getRegion($endpoint));
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
	 * endpoint config
	 *
	 * @var S3EndpointConfig
	 */
	private $endpoint;

	/**
	 * @var S3Credentials
	 */
	private $credentials;

	/**
	 * HTTP Verb
	 *
	 * @var string
	 */
	private $verb;
	
	/**
	 * bucket config
	 *
	 * @var S3BucketConfig
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
	private $resource;
	
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
	 * @var resource
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
	 * @var string
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
	 * @param S3BucketConfig|string $bucket Bucket config
	 * @param string $uri Object URI
	 * @param S3EndpointConfig $endpoint AWS endpoint URI
	 * @param S3Credentials|null $creds
	 */
	public function __construct($verb, $bucket = null, $uri = '', S3EndpointConfig $endpoint = null, S3Credentials $creds = null)
	{
		$this->endpoint = S3::getEndpoint($endpoint);
		$this->credentials = S3::getCredentials($creds);
		if ($bucket !== null) {
			$this->bucket = S3::makeBucketConfig($bucket, $this->endpoint);
		}

		$this->verb = $verb;
		$this->uri = $uri !== '' ? '/'.str_replace('%2F', '/', rawurlencode($uri)) : '/';

		$res = $this->endpoint->resolveHostUriAndResource($this->uri, $this->bucket);
		$this->headers['Host'] = $res['host'];
		$this->uri = $res['uri'];
		$this->resource = $res['resource'];

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
		if (count($this->parameters) > 0)
		{
			$query = substr($this->uri, -1) !== '?' ? '?' : '&';
			foreach ($this->parameters as $var => $value)
				if ($value === null || $value === '') $query .= $var.'&';
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
		$url = ($this->endpoint->useSSL ? 'https://' : 'http://') . ($this->headers['Host'] !== '' ? $this->headers['Host'] : $this->endpoint->hostname) . $this->uri;

		// Basic setup
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_USERAGENT, 'S3/php');

		if ('ON' === strtoupper(getenv('CURL_VERBOSE'))) {
			curl_setopt($curl, CURLOPT_VERBOSE, true);
		}

		if ($this->endpoint->useSSL)
		{
			// Set protocol version
			curl_setopt($curl, CURLOPT_SSLVERSION, $this->endpoint->useSSLVersion);

			// SSL Validation can now be optional for those with broken OpenSSL installations
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $this->endpoint->useSSLValidation ? 2 : 0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $this->endpoint->useSSLValidation ? 1 : 0);

			if ($this->endpoint->sslKey !== null) curl_setopt($curl, CURLOPT_SSLKEY, $this->endpoint->sslKey);
			if ($this->endpoint->sslCert !== null) curl_setopt($curl, CURLOPT_SSLCERT, $this->endpoint->sslCert);
			if ($this->endpoint->sslCACert !== null) curl_setopt($curl, CURLOPT_CAINFO, $this->endpoint->sslCACert);
		}

		curl_setopt($curl, CURLOPT_URL, $url);

		if ($this->endpoint->proxy !== null && isset($this->endpoint->proxy['host']))
		{
			curl_setopt($curl, CURLOPT_PROXY, $this->endpoint->proxy['host']);
			curl_setopt($curl, CURLOPT_PROXYTYPE, $this->endpoint->proxy['type']);
			/** @noinspection NotOptimalIfConditionsInspection */
			if (isset($this->endpoint->proxy['user'], $this->endpoint->proxy['pass']) && $this->endpoint->proxy['user'] !== null && $this->endpoint->proxy['pass'] !== null)
				curl_setopt($curl, CURLOPT_PROXYUSERPWD, sprintf('%s:%s', $this->endpoint->proxy['user'], $this->endpoint->proxy['pass']));
		}

		// Headers
		$httpHeaders = array(); 
		if (S3::hasAuth())
		{
			// Authorization string (CloudFront stringToSign should only contain a date)
			if ($this->endpoint->signatureVersion === S3::SigV2 || $this->headers['Host'] === 'cloudfront.amazonaws.com')
			{
				# TODO: Update CloudFront authentication
				foreach ($this->amzHeaders as $header => $value)
					if ($value !== '') $httpHeaders[] = $header.': '.$value;

				foreach ($this->headers as $header => $value)
					if ($value !== '') $httpHeaders[] = $header.': '.$value;

				$httpHeaders[] = 'Authorization: ' . S3::__getSignature($this->headers['Date'], $this->credentials);
			}
			else
			{
				$this->amzHeaders['x-amz-date'] = gmdate('Ymd\THis\Z');

				if (!isset($this->amzHeaders['x-amz-content-sha256'])) 
					$this->amzHeaders['x-amz-content-sha256'] = hash('sha256', $this->data);

				foreach ($this->amzHeaders as $header => $value)
					if ($value !== '') $httpHeaders[] = $header.': '.$value;

				foreach ($this->headers as $header => $value)
					if ($value !== '') $httpHeaders[] = $header.': '.$value;

				$authRegion = '';
				if ($this->bucket !== null) {
					$authRegion = $this->bucket->region;
				} elseif ($this->headers['Host'] === $this->endpoint->hostname) {
					$authRegion = $this->endpoint->defaultRegion;
				}

				if (empty($authRegion) && !empty(S3::$region)) {
					$authRegion = S3::$region;
				}

				$httpHeaders[] = 'Authorization: ' . S3::__getSignatureV4(
					$this->amzHeaders,
					$this->headers,
					$this->verb,
					$this->uri,
					$this->parameters,
					$this->credentials,
					$authRegion
				);

			}
		}

		curl_setopt($curl, CURLOPT_HTTPHEADER, $httpHeaders);
		curl_setopt($curl, CURLOPT_HEADER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, false);
		curl_setopt($curl, CURLOPT_WRITEFUNCTION, array(&$this, '__responseWriteCallback'));
		curl_setopt($curl, CURLOPT_HEADERFUNCTION, array(&$this, '__responseHeaderCallback'));
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);

		// Request types
		switch ($this->verb)
		{
			// case 'GET': break;
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

		// set curl progress function callback
		if (S3::$progressFunction) {
			curl_setopt($curl, CURLOPT_NOPROGRESS, false);
			curl_setopt($curl, CURLOPT_PROGRESSFUNCTION, S3::$progressFunction);
		}

		// Execute, grab errors
		if (curl_exec($curl))
			$this->response->code = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
		else
			$this->response->error = array(
				'code' => curl_errno($curl),
				'message' => curl_error($curl),
				'resource' => $this->resource
			);

		@curl_close($curl);

		// Parse body into XML
		if ($this->response->error === false && isset($this->response->headers['type'], $this->response->body)
			&& $this->response->headers['type'] === 'application/xml')
		{
			$this->response->body = simplexml_load_string($this->response->body);

			// Grab S3 errors
			if (isset($this->response->body->Code, $this->response->body->Message) &&
				!in_array($this->response->code, array(200, 204, 206), true))
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
	* CURL write callback
	*
	* @param resource &$curl CURL resource
	* @param string &$data Data
	* @return integer
	*/
	private function __responseWriteCallback(&$curl, &$data)
	{
		if ($this->fp !== false && in_array($this->response->code, array(200, 206), true))
			return fwrite($this->fp, $data);
		else
			$this->response->body .= $data;
		return strlen($data);
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
		if (strpos($data, 'HTTP') === 0)
			$this->response->code = (int)substr($data, 9, 3);
		else
		{
			$data = trim($data);
			if (strpos($data, ': ') === false) return $strlen;
			list($header, $value) = explode(': ', $data, 2);
			$header = strtolower($header);
			if ($header === 'last-modified')
				$this->response->headers['time'] = strtotime($value);
			elseif ($header === 'date')
				$this->response->headers['date'] = strtotime($value);
			elseif ($header === 'content-length')
				$this->response->headers['size'] = (int)$value;
			elseif ($header === 'content-type')
				$this->response->headers['type'] = $value;
			elseif ($header === 'etag')
				$this->response->headers['hash'] = $value{0} === '"' ? substr($value, 1, -1) : $value;
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
	public function __construct($message, $file, $line, $code = 0)
	{
		parent::__construct($message, $code);
		$this->file = $file;
		$this->line = $line;
	}

	public function __toString()
	{
		return sprintf('%s @ %s:%d', parent::__toString(), $this->file, $this->line);
	}
}

/**
 * S3EndpointConfig class
 */
final class S3EndpointConfig
{
	const AWS_S3_SUFFIX = '.amazonaws.com';
	const AWS_S3_SUFFIX_LENGTH = 14;

	const AWS_S3_DEFAULT_HOST = 's3.amazonaws.com';
	const AWS_S3_DEFAULT_REGION = 'us-east-1';

	/**
	 * Auth signature version
	 *
	 * @var string
	 */
	public $signatureVersion = S3::SigV4;

	/**
	 * Enable SSL
	 *
	 * @var bool
	 */
	public $useSSL = true;

	/**
	 * Use SSL version
	 *
	 * @var int constant as defined by curl module
	 */
	public $useSSLVersion = CURL_SSLVERSION_TLSv1;

	/**
	 * Enable SSL host & peer validation
	 *
	 * @var bool
	 */
	public $useSSLValidation = true;

	/**
	 * SSL client key
	 *
	 * @var string
	 */
	public $sslKey;

	/**
	 * SSL client certfificate
	 *
	 * @var string
	 */
	public $sslCert;

	/**
	 * SSL CA cert (only required if you are having problems with your system CA cert)
	 *
	 * @var string
	 */
	public $sslCACert;

	/**
	 * Hostname
	 *
	 * @var string
	 */
	public $hostname = self::AWS_S3_DEFAULT_HOST;

	/**
	 * default region
	 *
	 * @var string
	 */
	public $defaultRegion = self::AWS_S3_DEFAULT_REGION;

	/**
	 * Force Path-Style bucket reference in URL
	 *
	 * @var bool
	 */
	public $forcePathStyle = false;

	/**
	 * Proxy details
	 * @var array
	 */
	public $proxy;

	public function __construct($hostname = self::AWS_S3_DEFAULT_HOST, $defaultRegion = null)
	{
		if ($hostname === self::AWS_S3_DEFAULT_HOST) {
			$defaultRegion = self::AWS_S3_DEFAULT_REGION;
		}

		$this->hostname = $hostname;
		$this->defaultRegion = $defaultRegion;
	}

	/**
	 * If it is an AWS S3 endpoint, extract region code from the hostname.
	 * @see https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
	 *
	 * @return string
	 */
	public function getRegion()
	{
		// if not an AWS endpoint, return the default region
		if (1 !== preg_match("/s3[.-](?:website-|dualstack\.)?(.+)\.amazonaws\.com/i", $this->hostname, $match)) {
			return $this->defaultRegion;
		}

		if (strtolower($match[1]) === "external-1") {
			return $this->defaultRegion;
		}

		return $match[1];
	}

	/**
	 * Check DNS conformity
	 *
	 * @param string $bucket Bucket name
	 * @return boolean
	 */
	private function isDnsSafeName($bucket)
	{
		switch (true) {
			case strlen($bucket) > 63:
			case 0 !== preg_match("/[^a-z0-9\.-]/", $bucket):
			case $this->useSSL && strpos($bucket, '.') !== false:
			case strpos($bucket, '-.') !== false:
			case strpos($bucket, '..') !== false:
			case !preg_match('/^[0-9a-z]/', $bucket):
			case !preg_match('/[0-9a-z]$/', $bucket):
				return false;
		}

		return true;
	}

	/**
	 * @param $uri
	 * @param S3BucketConfig|null $bucket
	 * @return array
	 */
	public function resolveHostUriAndResource($uri, S3BucketConfig $bucket = null)
	{
		if ($bucket === null) {
			return array(
				'host' => $this->hostname,
				'uri' => $uri,
				'resource' => $uri,
			);
		}

		$pathStyle = $this->forcePathStyle || !$this->isDnsSafeName($bucket->name);

		if ($pathStyle) {
			return array(
				'host' => $this->hostname,
				'uri' => '/' . $bucket->name . $uri,
				'resource' => $uri,
			);
		}

		if ($this->hostname !== self::AWS_S3_DEFAULT_HOST || empty($bucket->region)) {
			$hostname = $bucket->name . '.' . $this->hostname;
		} else {
			$hostname = sprintf('%s.s3.%s.amazonaws.com', $bucket->name, $bucket->region);
		}

		return array(
			'host' => $hostname,
			'uri' => $uri,
			'resource' => '/' . $bucket->name . $uri,
		);
	}

	public function withHostname($hostname)
	{
		$this->hostname = $hostname;
		return $this;
	}

	public function withSSLEnabled($enabled = true)
	{
		$this->useSSL = $enabled;
		return $this;
	}

	public function withSSLValidationEnabled($enabled = true)
	{
		$this->useSSLValidation = $enabled;
		return $this;
	}

	public function withPathStyleEnabled($enabled = true)
	{
		$this->forcePathStyle = $enabled;
		return $this;
	}

	public function withSSLVersion($sslVersion = CURL_SSLVERSION_TLSv1)
	{
		$this->useSSLVersion = $sslVersion;
		return $this;
	}

	public function withSignatureVersion($version = S3::SigV4)
	{
		$this->signatureVersion = $version;
		return $this;
	}

	public function withDefaultRegion($defaultRegion)
	{
		$this->defaultRegion = $defaultRegion;
		return $this;
	}

	/**
	 * Set SSL client certificates (experimental)
	 *
	 * @param string $sslCert SSL client certificate
	 * @param string $sslKey SSL client key
	 * @param string $sslCACert SSL CA cert (only required if you are having problems with your system CA cert)
	 *
	 * @return self
	 */
	public function withSSLAuth($sslCert = null, $sslKey = null, $sslCACert = null)
	{
		$this->sslCert = $sslCert;
		$this->sslKey = $sslKey;
		$this->sslCACert = $sslCACert;

		return $this;
	}

	/**
	 * Set proxy information
	 *
	 * @param string $host Proxy hostname and port (localhost:1234)
	 * @param string $user Proxy username
	 * @param string $pass Proxy password
	 * @param int $type CURL proxy type
	 * @return self
	 */
	public function withProxy($host, $user = null, $pass = null, $type = CURLPROXY_SOCKS5)
	{
		$this->proxy = array(
			'host' => $host,
			'type' => $type,
			'user' => $user,
			'pass' => $pass
		);

		return $this;
	}
}

/**
 * S3BucketConfig class
 */
final class S3BucketConfig
{
	public $name;
	public $region;

	public function __construct($name, $region)
	{
		$this->name = $name;
		$this->region = $region;
	}

	public function __toString()
	{
		return $this->name;
	}
}

/**
 * S3Credentials class
 */
final class S3Credentials
{
	public $accessKey;
	public $secretKey;

	public function __construct($accessKey, $secretKey)
	{
		$this->accessKey = $accessKey;
		$this->secretKey = $secretKey;
	}

	public function isInitialised()
	{
		return $this->accessKey !== null && $this->secretKey !== null;
	}
}
