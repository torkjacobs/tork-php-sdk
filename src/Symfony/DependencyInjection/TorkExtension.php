<?php

declare(strict_types=1);

namespace Tork\Governance\Symfony\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;
use Tork\Governance\Core\Tork;
use Tork\Governance\Middleware\SymfonyMiddleware;

/**
 * Symfony DI extension for Tork Governance.
 */
class TorkExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // Register Tork service
        $container->register(Tork::class)
            ->setArgument('$config', [
                'defaultAction' => $config['default_action'],
                'policyVersion' => $config['policy_version'],
                'customPatterns' => $config['custom_patterns'],
            ])
            ->setPublic(true);

        // Register middleware
        $container->register(SymfonyMiddleware::class)
            ->setArgument('$tork', new Reference(Tork::class))
            ->setArgument('$options', $config['middleware'])
            ->addTag('kernel.event_subscriber')
            ->setPublic(true);
    }
}
