/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Nikolas Charalambidis
 */

package dev.nichar.facepalm.engine;

/**
 * A scoring rule's requested change to a finding's risk and confidence.
 * Values are recorded before {@link Finding#log(String, int, int)} clamps the resulting scores.
 *
 * @param name name of the scoring rule
 * @param risk requested risk change
 * @param confidence requested confidence change
 */
public record ScoreAdjustment(String name, int risk, int confidence) {
}
