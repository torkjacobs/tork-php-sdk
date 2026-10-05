<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Tork\Governance\Core\Tork;

final class SessionContextTest extends TestCase
{
    public function testPassesAllFourFieldsThrough(): void
    {
        $r = (new Tork())->govern('Hello', sessionContext: [
            'agent_id' => 'agent-7',
            'agent_role' => 'planner',
            'session_id' => 'sess-1',
            'session_turn' => 3,
        ]);

        $this->assertSame(
            ['agent_id' => 'agent-7', 'agent_role' => 'planner', 'session_id' => 'sess-1', 'session_turn' => 3],
            $r->sessionContext
        );
        $this->assertSame($r->sessionContext, $r->toArray()['session_context']);
        $this->assertIsInt($r->toArray()['session_context']['session_turn']);
    }

    public function testOmitsTheFieldWhenNotSet(): void
    {
        $r = (new Tork())->govern('Hello');
        $this->assertNull($r->sessionContext);
        $this->assertArrayNotHasKey('session_context', $r->toArray());
    }

    public function testOmitsEmptyContextAndNullFields(): void
    {
        $empty = (new Tork())->govern('Hello', sessionContext: []);
        $this->assertArrayNotHasKey('session_context', $empty->toArray());

        $nulls = (new Tork())->govern('Hello', sessionContext: ['agent_id' => null, 'session_turn' => null]);
        $this->assertArrayNotHasKey('session_context', $nulls->toArray());
    }

    public function testPartialContextKeepsOnlyTheFieldsSet(): void
    {
        $r = (new Tork())->govern('Hello', sessionContext: ['agent_id' => 'a', 'session_id' => null]);
        $this->assertSame(['agent_id' => 'a'], $r->toArray()['session_context']);
    }

    public function testUnknownKeysAreDropped(): void
    {
        $r = (new Tork())->govern('Hello', sessionContext: ['agent_id' => 'a', 'secret' => 'x']);
        $this->assertSame(['agent_id' => 'a'], $r->sessionContext);
    }

    public function testSessionTurnMustBeAnInteger(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Tork())->govern('Hello', sessionContext: ['session_turn' => '3']);
    }

    public function testStringFieldsMustBeStrings(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Tork())->govern('Hello', sessionContext: ['agent_id' => 42]);
    }

    public function testContextDoesNotAffectDetection(): void
    {
        $r = (new Tork())->govern('mail jane@example.com', sessionContext: ['agent_id' => 'a']);
        $this->assertSame('redact', $r->action);
        $this->assertStringContainsString('[EMAIL_REDACTED]', $r->output);
    }
}
