/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Nikolas Charalambidis
 */

package dev.nichar.facepalm.engine.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import dev.nichar.facepalm.FacepalmConfig;
import dev.nichar.facepalm.TestContainer;
import dev.nichar.facepalm.engine.FileContext;
import dev.nichar.facepalm.engine.Finding;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class ExtractorPropertiesTest {

    /**
     * Credential characters that do not include the mask's own marker.
     */
    private static final String CREDENTIAL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /**
     * Extractor shared by all tries; building a Guice container per sample is slow.
     */
    private static final RegexSecretExtractor EXTRACTOR = TestContainer.create(new FacepalmConfig())
        .getInstance(RegexSecretExtractor.class);

    @Property(tries = 100, seed = "371")
    void captured_secret_is_masked_at_every_length(@ForAll("secrets") final String secret) {
        final var prefix = "password=";
        final var rawLine = prefix + secret;
        final var masked = SnippetMasker.mask(rawLine, List.of(new int[] {
            prefix.length(), rawLine.length() }));

        assertThat(masked).startsWith(prefix);
        final var value = masked.substring(prefix.length());
        assertThat(value).doesNotContain(secret);
        if (secret.length() < 8) {
            assertThat(value).isEqualTo("****");
        } else {
            final var ends = value.split("\\.\\.\\.", -1);
            assertThat(ends).hasSize(2);
            assertThat(ends[0]).hasSize(ends[1].length()).hasSizeLessThanOrEqualTo(4);
            assertThat(ends[0].length() + ends[1].length()).isLessThanOrEqualTo(secret.length() / 4);
            assertThat(secret).startsWith(ends[0]).endsWith(ends[1]);
        }
    }

    @Property(tries = 100, seed = "371")
    void extraction_agrees_for_lf_and_crlf(@ForAll("detectableSecrets") final String secret) {
        final var lines = List.of("# header", "password=" + secret, "-----BEGIN " + "PRIVATE KEY-----",
            "MIIBVQIBADANBgkqhkiG9w0BAQEFAASC", "-----END " + "PRIVATE KEY-----");
        final var lf = extract(String.join("\n", lines));
        final var crlf = extract(String.join("\r\n", lines));

        assertThat(lf).hasSizeGreaterThanOrEqualTo(2);
        assertThat(lf).extracting(Finding::getSecretValue).contains(secret);
        assertThat(crlf.stream().map(ExtractorPropertiesTest::findingSummary)).containsExactlyElementsOf(
            lf.stream().map(ExtractorPropertiesTest::findingSummary).toList());
    }

    @Property(tries = 100, seed = "371")
    void every_offset_maps_to_its_regex_line(@ForAll("contents") final String generated) {
        final var content = "\r\n" + generated;
        final var index = new LineIndex(content);
        final var breaks = new ArrayList<Integer>();
        final var matcher = Pattern.compile("\\R").matcher(content);
        while (matcher.find()) {
            breaks.add(matcher.end());
        }

        for (int offset = 0; offset <= content.length(); offset++) {
            final int current = offset;
            final long previousBreaks = breaks.stream().filter(end -> end <= current).count();
            assertThat(index.lineNumberAt(offset)).as("offset %s in %s", offset, content).isEqualTo(previousBreaks + 1);
        }
    }

    @Provide
    Arbitrary<String> secrets() {
        return Arbitraries.strings().withChars(CREDENTIAL_CHARS.toCharArray()).ofMinLength(1).ofMaxLength(128);
    }

    @Provide
    Arbitrary<String> detectableSecrets() {
        return Arbitraries.strings().withChars(CREDENTIAL_CHARS.toCharArray()).ofMinLength(8).ofMaxLength(30)
            .map(middle -> "Ab3" + middle);
    }

    @Provide
    Arbitrary<String> contents() {
        return Arbitraries.strings()
            .withChars('a', 'b', '\r', '\n', '\u000B', '\u000C', '\u0085', '\u2028', '\u2029')
            .ofMaxLength(100);
    }

    private static List<Finding> extract(final String content) {
        return EXTRACTOR.extract(new FileContext(Path.of("app.properties"), content, Arrays.asList(content.split(
            "\\R"))));
    }

    private static List<Object> findingSummary(final Finding finding) {
        // Multi-line matches preserve the source's line separators in their raw value.
        return List.of(finding.getPatternName(), finding.getSecretValue().replace("\r\n", "\n"), finding
            .getLineNumber(),
            finding.getContextSnippet());
    }
}
