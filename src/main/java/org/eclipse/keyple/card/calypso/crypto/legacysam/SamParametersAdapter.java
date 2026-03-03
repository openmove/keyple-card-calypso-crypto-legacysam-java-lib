/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.crypto.legacysam;

import org.eclipse.keypop.calypso.crypto.legacysam.sam.SamParameters;

/**
 * Implementation of {@link SamParameters}.
 *
 * @since 0.9.0
 */
public class SamParametersAdapter implements SamParameters {
  private final byte[] samParameters;

  SamParametersAdapter(byte[] samParameters) {
    this.samParameters = samParameters;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public byte[] getRawData() {
    return samParameters;
  }
}
