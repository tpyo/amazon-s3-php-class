<?php

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;

class S3Test extends S3BaseTest {

    const TEST_STRING_CONTENT = "<strong>Hi</strong> I'm a test content";
    const TEST_STRING_MIME_TYPE = "text/html; charset=utf-8";
    const TEST_X_FOO_HEADER = "header value";
    const TEST_CACHE_CONTROL = 'public,max-age=31536000';

    public function setUp(): void {
        S3BaseTest::setUp();
        $this->setUpS3Client();
    }

    public function testGetBucket() {
        $bucket = S3::getBucket( $this->s3Bucket );
        $files = array_keys($bucket);

        $this->assertContains( self::PRIVATE_OBJECT, $files );
        $this->assertContains( self::PUBLIC_OBJECT, $files );
    }

    /**
     * @param string $uri
     * @param ?int $expectedSize
     * @dataProvider getObjectInfoProvider
     */
    public function testGetObjectInfo( string $uri, ?int $expectedSize ) {
        $obj = S3::getObjectInfo( $this->s3Bucket, $uri );

        if ($expectedSize === null) {
            $this->assertFalse($obj);
        }
        else {
            $this->assertEquals($expectedSize, $obj['size']);
        }
    }

    /**
     * Refer to .github/workflows/phpunit.yml for the test files content.
     */
    public function getObjectInfoProvider(): Generator {
        yield 'public file' => [
            self::PUBLIC_OBJECT, 4
        ];
        yield 'private file' => [
            self::PRIVATE_OBJECT, 20
        ];
        yield 'not existing file file' => [
            self::NOT_EXISTING_OBJECT, null
        ];
    }

    /**
     * @throws GuzzleException
     * @dataProvider putObjectProvider
     */
    public function testPutObject(string $acl = S3::ACL_PUBLIC_READ ) {
        $uri = uniqid('s3-test-') . '.html';

        $res = S3::putObject(
            self::TEST_STRING_CONTENT,
            $this->s3Bucket,
            $uri,
            $acl,
            [
                // this will be returned as x-amz-meta-x-foo
                'X-Foo' => self::TEST_X_FOO_HEADER,
            ],
            [
                'Content-Type' => self::TEST_STRING_MIME_TYPE,
                'Cache-Control' => self::TEST_CACHE_CONTROL
            ]
        );

        $this->assertTrue($res, 'putObjectString() was successful');

        // check the upload
        $obj = S3::getObjectInfo($this->s3Bucket, $uri);

        $this->assertEquals(strlen(self::TEST_STRING_CONTENT), $obj['size']);
        $this->assertEquals(self::TEST_X_FOO_HEADER, $obj['x-amz-meta-x-foo']);
        $this->assertEquals(self::TEST_STRING_MIME_TYPE, $obj['type']);

        $files = array_keys(S3::getBucket($this->s3Bucket));
        $this->assertContains( $uri, $files, 'The uploaded file is in the bucket' );

        // check the public access
        if ($acl === S3::ACL_PUBLIC_READ) {
            $resp = $this->getGuzzleClient()->get($uri);

            $this->assertEquals(200, $resp->getStatusCode());

            // check the body
            $this->assertEquals(strlen(self::TEST_STRING_CONTENT), $resp->getBody()->getSize());
            $this->assertEquals(self::TEST_STRING_CONTENT, $resp->getBody()->getContents());

            // check the headers
            $this->assertEquals(self::TEST_CACHE_CONTROL, $resp->getHeader('cache-control')[0]);
            $this->assertEquals(self::TEST_STRING_MIME_TYPE, $resp->getHeader('content-type')[0]);
            $this->assertEquals(self::TEST_X_FOO_HEADER, $resp->getHeader('x-amz-meta-x-foo')[0]);
        }
        elseif ( $acl == S3::ACL_PRIVATE ) {
            try {
                $this->getGuzzleClient()->get($uri);
            }
            catch (ClientException $ex) {
                $this->assertEquals(403, $ex->getResponse()->getStatusCode());
            }
        }

        // remove it
        $res = S3::deleteObject($this->s3Bucket, $uri);
        $this->assertTrue($res, 'deleteObject() was successful');

        $files = array_keys(S3::getBucket($this->s3Bucket));
        $this->assertNotContains( $uri, $files, 'The uploaded file has been removed the bucket' );
    }

    public function putObjectProvider(): Generator {
        yield 'public ACL' => [ S3::ACL_PUBLIC_READ ];
        yield 'private ACL' => [ S3::ACL_PRIVATE ];
    }

}
