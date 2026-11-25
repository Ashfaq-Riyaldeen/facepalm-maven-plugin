/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Nikolas Charalambidis
 */

package dev.nichar.facepalm.engine;

import static org.assertj.core.api.Assertions.assertThat;

import dev.nichar.facepalm.config.ScoringConfig;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class FindingPropertiesTest {

    @Property(tries = 100, seed = "371")
    void evaluator_adjustments_keep_every_score_bounded(@ForAll("scores") final int risk,
                                                        @ForAll("scores") final int confidence,
                                                        @ForAll("adjustmentSequences") final List<Adjustment> adjustments,
                                                        @ForAll final ScoringStrategy strategy) {
        final var finding = Finding.builder()
            .patternName("Test")
            .deduplicationHash("hash")
            .secretValue("test-secret")
            .riskScore(risk)
            .confidenceScore(confidence)
            .build();
        final var config = new ScoringConfig();
        config.setStrategy(strategy);

        assertScoresInRange(finding, config);
        for (final var adjustment : adjustments) {
            finding.log(adjustment.name(), adjustment.risk(), adjustment.confidence());
            assertScoresInRange(finding, config);
        }
    }

    @Provide
    Arbitrary<Integer> scores() {
        return Arbitraries.integers().between(0, 100);
    }

    @Provide
    Arbitrary<List<Adjustment>> adjustmentSequences() {
        final var delta = Arbitraries.integers().between(-200, 200);
        return Combinators.combine(Arbitraries.just("Rule"), delta, delta)
            .as(Adjustment::new)
            .list().ofMaxSize(12);
    }

    private static void assertScoresInRange(final Finding finding, final ScoringConfig config) {
        assertThat(finding.getRiskScore()).isBetween(0, 100);
        assertThat(finding.getConfidenceScore()).isBetween(0, 100);
        assertThat(finding.getNumericScore(config)).isBetween(0.0, 100.0);
    }

    private record Adjustment(String name, int risk, int confidence) {
    }
}
