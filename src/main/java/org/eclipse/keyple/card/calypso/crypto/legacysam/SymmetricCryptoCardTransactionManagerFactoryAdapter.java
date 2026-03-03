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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoCardTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerSpi;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardResponseApi;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;

/**
 * Adapter of {@link SymmetricCryptoCardTransactionManagerFactory}.
 *
 * @since 0.4.0
 */
final class SymmetricCryptoCardTransactionManagerFactoryAdapter
    implements SymmetricCryptoCardTransactionManagerFactory,
        SymmetricCryptoCardTransactionManagerFactorySpi {

  private final ProxyReaderApi samReader;
  private final LegacySamAdapter sam;
  private final boolean isExtendedModeSupported;
  private final int maxCardApduLengthSupported;

  SymmetricCryptoCardTransactionManagerFactoryAdapter(
      ProxyReaderApi samReader, LegacySamAdapter sam, ContextSettingAdapter contextSetting) {
    this.samReader = samReader;
    this.sam = sam;
    this.isExtendedModeSupported =
        sam.getProductType() == LegacySam.ProductType.SAM_C1
            || sam.getProductType() == LegacySam.ProductType.HSM_C1;
    this.maxCardApduLengthSupported =
        contextSetting.getContactReaderPayloadCapacity() != null
            ? Math.min(
                sam.getMaxDigestDataLength(), contextSetting.getContactReaderPayloadCapacity())
            : sam.getMaxDigestDataLength();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public boolean isExtendedModeSupported() {
    return isExtendedModeSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public int getMaxCardApduLengthSupported() {
    return maxCardApduLengthSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public void preInitTerminalSessionContext()
      throws SymmetricCryptoException, SymmetricCryptoIOException {
    processCommand(new CommandGetChallenge(new DtoAdapters.CommandContextDto(sam, null, null), 8));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoCardTransactionManagerSpi createCardTransactionManager(
      byte[] cardKeyDiversifier, boolean useExtendedMode, List<byte[]> transactionAuditData) {
    if (useExtendedMode && !isExtendedModeSupported) {
      throw new IllegalStateException("The extended mode is not supported by the crypto service");
    }
    return new SymmetricCryptoCardTransactionManagerAdapter(
        samReader,
        sam,
        cardKeyDiversifier,
        useExtendedMode,
        maxCardApduLengthSupported,
        transactionAuditData);
  }

  private void processCommand(Command command)
      throws SymmetricCryptoException, SymmetricCryptoIOException {
    List<byte[]> transactionAuditData = new ArrayList<>();
    try {
      // Get the list of C-APDU to transmit
      List<ApduRequestSpi> apduRequests =
          CardTransactionUtil.getApduRequests(Collections.singletonList(command));

      // Wrap the list of C-APDUs into a card request
      CardRequestSpi cardRequest = new DtoAdapters.CardRequestAdapter(apduRequests, true);

      // Transmit the commands to the SAM
      CardResponseApi cardResponse =
          CardTransactionUtil.transmitCardRequest(
              cardRequest, samReader, sam, transactionAuditData);

      ApduResponseApi apduResponse =
          cardResponse.getApduResponses().get(0); // Assuming only one response.

      command.parseResponse(apduResponse);
    } catch (CommandException e) {
      CommandRef commandRef = command.getCommandRef();
      String sw =
          (command.getApduResponse() != null)
              ? HexUtil.toHex(command.getApduResponse().getStatusWord())
              : "null";

      String errorMessage =
          CardTransactionUtil.MSG_SAM_COMMAND_ERROR
              + "while processing response to SAM command: "
              + commandRef
              + "["
              + sw
              + "]";
      String detailedErrorMessage =
          CardTransactionUtil.MSG_SAM_COMMAND_ERROR
              + "while processing response to SAM command: "
              + commandRef
              + "["
              + sw
              + "]"
              + CardTransactionUtil.getTransactionAuditDataAsString(transactionAuditData, sam);

      throw new SymmetricCryptoException(
          errorMessage, new UnexpectedCommandStatusException(detailedErrorMessage, e));
    }
  }
}
