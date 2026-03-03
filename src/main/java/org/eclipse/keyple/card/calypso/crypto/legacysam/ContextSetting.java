/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

/**
 * Contains additional parameters for the management of context specific cases.
 *
 * @since 0.4.0
 */
public interface ContextSetting {

  /**
   * Defines the maximum size of APDUs that the library can generate when communicating with a
   * contact card.
   *
   * @param payloadCapacity A positive integer lower than 255.
   * @return The object instance.
   * @since 0.4.0
   */
  ContextSetting setContactReaderPayloadCapacity(int payloadCapacity);
}
