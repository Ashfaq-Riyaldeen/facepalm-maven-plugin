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
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class FindingPropertiesTest {

    @Property(tries = 200)
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
        return Arbitraries.of(
            new Adjustment("Mock Context", 0, -40),
            new Adjustment("Production Context", 20, 0),
            new Adjustment("Low Exposure", -40, 0),
            new Adjustment("High Volume", -25, -30),
            new Adjustment("Composite Risk", 15, 10),
            new Adjustment("Placeholder", -50, -100),
            new Adjustment("Dummy Keyword", 0, -80),
            new Adjustment("Configuration File", 15, 20),
            new Adjustment("Documentation File", -30, -40),
            new Adjustment("High Entropy", 10, 20),
            new Adjustment("Test Path", -30, -20))
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
