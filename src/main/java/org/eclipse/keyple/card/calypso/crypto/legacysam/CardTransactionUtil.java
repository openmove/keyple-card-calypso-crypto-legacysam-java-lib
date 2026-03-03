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
import java.util.List;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.ReaderIOException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SamIOException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Util to build and transmit APDU requests.
 *
 * @since 2.0.0
 */
class CardTransactionUtil {
  private static final Logger logger = LoggerFactory.getLogger(CardTransactionUtil.class);
  /* Prefix/suffix used to compose exception messages */
  private static final String MSG_SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred ";
  private static final String MSG_SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred ";
  private static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands";
  static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";

  private CardTransactionUtil() {}

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link Command}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 2.0.0
   */
  static List<ApduRequestSpi> getApduRequests(List<Command> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<>();
    if (commands != null) {
      for (Command command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @return The card response.
   * @since 2.0.0
   */
  static CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest,
      ProxyReaderApi samReader,
      LegacySamAdapter sam,
      List<byte[]> transactionAuditData)
      throws SymmetricCryptoIOException {
    CardResponseApi cardResponse;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse(), transactionAuditData);
      throw new SymmetricCryptoIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new ReaderIOException(
              MSG_SAM_READER_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(transactionAuditData, sam),
              e));
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse(), transactionAuditData);
      throw new SymmetricCryptoIOException(
          MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new SamIOException(
              MSG_SAM_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(transactionAuditData, sam),
              e));
    } catch (UnexpectedStatusWordException e) {
      cardResponse = e.getCardResponse();
    }
    saveTransactionAuditData(cardRequest, cardResponse, transactionAuditData);
    return cardResponse;
  }

  /**
   * Saves the provided exchanged APDU commands in the list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   * @param transactionAuditData The audit data list.
   * @since 2.0.0
   */
  private static void saveTransactionAuditData(
      CardRequestSpi cardRequest, CardResponseApi cardResponse, List<byte[]> transactionAuditData) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * Returns a string representation of the transaction audit data.
   *
   * @return A not empty string.
   * @since 2.0.0
   */
  static String getTransactionAuditDataAsString(
      List<byte[]> transactionAuditData, LegacySamAdapter sam) {
    return "\nTransaction audit JSON data: {"
        + "\"sam\":"
        + sam
        + ",\"apdus\":"
        + JsonUtil.toJson(transactionAuditData)
        + "}";
  }
}
