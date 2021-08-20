<?php

use GuzzleHttp\Client;
use PHPUnit\Framework\TestCase;

class S3BaseTest extends TestCase {

    const PUBLIC_OBJECT = 'README';
    const PRIVATE_OBJECT = '.private';
    const NOT_EXISTING_OBJECT = 'does-not-exist.foo';

    /** @var string */
    protected $s3AccessKey;
    /** @var string */
    protected $s3SecretKey;
    /** @var string e.g. test.macbre.net */
    protected $s3Bucket;
    /** @var string e.g. eu-west-1 */
    protected $s3Region;

    /**
     * Refer to tests/README.md on how to set up your local testing env.
     */
    public function setUp(): void {
        $this->s3AccessKey = getenv( 'S3_ACCESS_KEY' );
        $this->s3SecretKey = getenv( 'S3_SECRET_KEY' );
        $this->s3Bucket = getenv( 'S3_BUCKET' );
        $this->s3Region = getenv( 'S3_REGION' );
    }

    protected function getGuzzleClient(): Client {
        return new Client([
            // e.g. https://s3-eu-west-1.amazonaws.com/s.elecena.pl/3/0/2/302ce20dd5246383abf85a5a017d6b9a.jpg
            'base_uri' => sprintf('https://s3-%s.amazonaws.com/%s/', $this->s3Region, $this->s3Bucket),
        ]);
    }

    protected function setUpS3Client( bool $useSSL = true ) {
        S3::setAuth($this->s3AccessKey, $this->s3SecretKey);
        S3::setSSL($useSSL);

        // provide the region as it's needed when using https
        S3::$endpoint = sprintf('s3-%s.amazonaws.com', $this->s3Region);

        S3::$region = $this->s3Region;
    }

    public function testClassIsPresentInAutoloader() {
        $this->assertTrue( class_exists( S3::class ) );
    }
}
