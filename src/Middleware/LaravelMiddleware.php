<?php

declare(strict_types=1);

namespace Tork\Governance\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tork\Governance\Core\Tork;
use Tork\Governance\Core\GovernanceReceipt;

/**
 * Laravel middleware for Tork Governance.
 *
 * Provides automatic PII detection and redaction for
 * Laravel HTTP requests and responses.
 */
class LaravelMiddleware
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

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response|JsonResponse
    {
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

        // Store tork instance and receipts in request
        $request->attributes->set('tork', $this->tork);
        $request->attributes->set('torkReceipts', $this->receipts);

        // Process request
        $response = $next($request);

        // Govern response
        if ($this->options['governOutput']) {
            $response = $this->governResponse($response);
        }

        return $response;
    }

    /**
     * Govern request body content.
     */
    private function governRequestBody(Request $request): void
    {
        $contentType = $request->header('Content-Type', '');

        if (str_contains($contentType, 'application/json')) {
            $data = $request->json()->all();
            $governed = $this->governArray($data);
            $request->json()->replace($governed);
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
     * Govern response content.
     */
    private function governResponse(Response|JsonResponse $response): Response|JsonResponse
    {
        if ($response instanceof JsonResponse) {
            $data = $response->getData(true);
            $governed = $this->governArray($data);
            $response->setData($governed);
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

        return $response;
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
}
