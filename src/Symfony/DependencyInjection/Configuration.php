<?php

declare(strict_types=1);

namespace Tork\Governance\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Symfony bundle configuration for Tork Governance.
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('tork');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('default_action')
                    ->defaultValue('redact')
                    ->info('Default action when PII is detected: redact, deny, allow')
                ->end()
                ->scalarNode('policy_version')
                    ->defaultValue('1.0.0')
                    ->info('Version identifier for your governance policy')
                ->end()
                ->arrayNode('middleware')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('governInput')->defaultTrue()->end()
                        ->booleanNode('governOutput')->defaultTrue()->end()
                        ->booleanNode('governBody')->defaultTrue()->end()
                    ->end()
                ->end()
                ->arrayNode('custom_patterns')
                    ->scalarPrototype()->end()
                    ->info('Custom regex patterns for PII detection')
                ->end()
            ->end();

        return $treeBuilder;
    }
}
