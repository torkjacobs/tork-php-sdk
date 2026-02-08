<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Tork\Governance\Core\Tork;
use Tork\Governance\Core\GovernanceResult;
use Tork\Governance\Core\GovernanceReceipt;

class TorkGovernanceTest extends TestCase
{
    private Tork $tork;

    protected function setUp(): void
    {
        $this->tork = new Tork();
    }

    public function testGovernReturnsGovernanceResult(): void
    {
        $result = $this->tork->govern("Hello world");
        $this->assertInstanceOf(GovernanceResult::class, $result);
    }

    public function testCleanTextIsAllowed(): void
    {
        $result = $this->tork->govern("Hello world");
        $this->assertEquals('allow', $result->action);
        $this->assertEquals('Hello world', $result->output);
    }

    public function testDetectsSSN(): void
    {
        $result = $this->tork->govern("My SSN is 123-45-6789");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[SSN_REDACTED]', $result->output);
        $this->assertStringNotContainsString('123-45-6789', $result->output);
    }

    public function testDetectsEmail(): void
    {
        $result = $this->tork->govern("Contact john@example.com for details");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[EMAIL_REDACTED]', $result->output);
        $this->assertStringNotContainsString('john@example.com', $result->output);
    }

    public function testDetectsPhone(): void
    {
        $result = $this->tork->govern("Call me at 555-123-4567");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[PHONE_REDACTED]', $result->output);
    }

    public function testDetectsCreditCard(): void
    {
        $result = $this->tork->govern("Card: 4111-1111-1111-1111");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[CREDIT_CARD_REDACTED]', $result->output);
    }

    public function testDetectsIPAddress(): void
    {
        $result = $this->tork->govern("Server IP: 192.168.1.1");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[IP_ADDRESS_REDACTED]', $result->output);
    }

    public function testRedactsMultiplePII(): void
    {
        $result = $this->tork->govern("SSN: 123-45-6789, Email: test@example.com");
        $this->assertEquals('redact', $result->action);
        $this->assertStringContainsString('[SSN_REDACTED]', $result->output);
        $this->assertStringContainsString('[EMAIL_REDACTED]', $result->output);
    }

    public function testReceiptGeneration(): void
    {
        $result = $this->tork->govern("My SSN is 123-45-6789");
        $this->assertInstanceOf(GovernanceReceipt::class, $result->receipt);
        $this->assertStringStartsWith('tork_', $result->receipt->receiptId);
    }

    public function testReceiptToArray(): void
    {
        $result = $this->tork->govern("test");
        $data = $result->receipt->toArray();
        $this->assertArrayHasKey('receiptId', $data);
        $this->assertArrayHasKey('timestamp', $data);
        $this->assertArrayHasKey('action', $data);
        $this->assertArrayHasKey('policyVersion', $data);
    }

    public function testResultToArray(): void
    {
        $result = $this->tork->govern("test");
        $data = $result->toArray();
        $this->assertArrayHasKey('action', $data);
        $this->assertArrayHasKey('output', $data);
        $this->assertArrayHasKey('pii', $data);
        $this->assertArrayHasKey('receipt', $data);
    }

    public function testEmptyStringIsAllowed(): void
    {
        $result = $this->tork->govern("");
        $this->assertEquals('allow', $result->action);
    }

    public function testCustomConfig(): void
    {
        $tork = new Tork(['defaultAction' => 'deny']);
        $result = $tork->govern("SSN: 123-45-6789");
        $this->assertEquals('deny', $result->action);
        $this->assertStringNotContainsString('[SSN_REDACTED]', $result->output);
    }

    public function testPolicyVersion(): void
    {
        $tork = new Tork(['policyVersion' => '2.0.0']);
        $result = $tork->govern("test");
        $this->assertEquals('2.0.0', $result->receipt->policyVersion);
    }

    public function testPiiTypesInReceipt(): void
    {
        $result = $this->tork->govern("SSN: 123-45-6789, Email: test@test.com");
        $this->assertContains('SSN', $result->receipt->piiTypesDetected);
        $this->assertContains('EMAIL', $result->receipt->piiTypesDetected);
    }

    public function testNoPiiInReceipt(): void
    {
        $result = $this->tork->govern("Clean text");
        $this->assertEmpty($result->receipt->piiTypesDetected);
    }
}
