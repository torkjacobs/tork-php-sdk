<?php

declare(strict_types=1);

namespace Tork\Governance\Middleware;

use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Tork\Governance\Core\Tork;

/**
 * Symfony event subscriber for Tork Governance.
 *
 * Provides automatic PII detection and redaction for
 * Symfony HTTP requests and responses.
 */
class SymfonyMiddleware implements EventSubscriberInterface
{
    private Tork $tork;
    private array $options;
    private array $receipts = [];

    public function __construct(?Tork $tork = null, array $options = [])
    {
        $this->tork = $tork ?? new Tork();
        $this->options = array_merge([
            'governInput' => true,
            'governOutput' => true,
            'governBody' => true,
        ], $options);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 100],
            KernelEvents::RESPONSE => ['onKernelResponse', -100],
        ];
    }

    /**
     * Handle incoming request.
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        // Govern query parameters
        if ($this->options['governInput']) {
            foreach ($request->query->all() as $key => $value) {
                if (is_string($value)) {
                    $result = $this->tork->govern($value);
                    $this->receipts[] = $result->receipt;
                    if ($result->action === 'redact') {
                        $request->query->set($key, $result->output);
                    }
                }
            }
        }

        // Govern request body
        if ($this->options['governInput'] && $this->options['governBody']) {
            $this->governRequestBody($request);
        }

        // Store tork instance and receipts
        $request->attributes->set('tork', $this->tork);
        $request->attributes->set('torkReceipts', $this->receipts);
    }

    /**
     * Handle outgoing response.
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        if (!$this->options['governOutput']) {
            return;
        }

        $response = $event->getResponse();

        if ($response instanceof JsonResponse) {
            $data = json_decode($response->getContent(), true);
            if (is_array($data)) {
                $governed = $this->governArray($data);
                $response->setData($governed);
            }
        } elseif (str_contains($response->headers->get('Content-Type', ''), 'text/')) {
            $content = $response->getContent();
            if ($content !== false) {
                $result = $this->tork->govern($content);
                $this->receipts[] = $result->receipt;
                if ($result->action === 'redact') {
                    $response->setContent($result->output);
                }
            }
        }
    }

    /**
     * Govern request body content.
     */
    private function governRequestBody($request): void
    {
        $contentType = $request->headers->get('Content-Type', '');

        if (str_contains($contentType, 'application/json')) {
            $data = json_decode($request->getContent(), true);
            if (is_array($data)) {
                $governed = $this->governArray($data);
                // Store governed data for controller access
                $request->attributes->set('_governed_body', $governed);
            }
        } elseif (str_contains($contentType, 'application/x-www-form-urlencoded') ||
                  str_contains($contentType, 'multipart/form-data')) {
            foreach ($request->request->all() as $key => $value) {
                if (is_string($value)) {
                    $result = $this->tork->govern($value);
                    $this->receipts[] = $result->receipt;
                    if ($result->action === 'redact') {
                        $request->request->set($key, $result->output);
                    }
                }
            }
        }
    }

    /**
     * Recursively govern array values.
     */
    private function governArray(array $data): array
    {
        $governed = [];

        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $result = $this->tork->govern($value);
                $this->receipts[] = $result->receipt;
                $governed[$key] = $result->action === 'redact' ? $result->output : $value;
            } elseif (is_array($value)) {
                $governed[$key] = $this->governArray($value);
            } else {
                $governed[$key] = $value;
            }
        }

        return $governed;
    }

    /**
     * Get collected receipts.
     */
    public function getReceipts(): array
    {
        return $this->receipts;
    }

    /**
     * Get Tork instance.
     */
    public function getTork(): Tork
    {
        return $this->tork;
    }
}
