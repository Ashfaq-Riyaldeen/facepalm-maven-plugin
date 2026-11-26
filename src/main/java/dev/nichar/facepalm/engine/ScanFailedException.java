/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Nikolas Charalambidis
 */

package dev.nichar.facepalm.engine;

import java.io.Serial;

/**
 * The scan failed under the configured policy for findings or incomplete scans.
 * The Mojos turn it into a {@code MojoFailureException} with the same message.
 */
public class ScanFailedException extends Exception {

    /**
     * Serialization version of this exception.
     */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param message why the scan failed
     */
    public ScanFailedException(final String message) {
        super(message);
    }
}
