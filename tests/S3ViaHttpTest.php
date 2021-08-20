<?php

class S3ViaHttpTest extends S3Test {

    public function setUp(): void {
        S3BaseTest::setUp();
        $this->setUpS3Client( false );
    }

}
