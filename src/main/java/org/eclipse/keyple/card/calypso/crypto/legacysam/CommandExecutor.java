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
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.InconsistentDataException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.ReaderIOException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SamIOException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;

/**
 * Utility class to factorize command management.
 *
 * @since 0.3.0
 */
final class CommandExecutor {
  private static final String MSG_SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred ";
  private static final String MSG_SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred ";
  private static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";
  private static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands";

  private CommandExecutor() {}

  /**
   * Requests the execution of all commands provided by the SAM inserted in the supplied card
   * reader, and finalizes any commands that require it.
   *
   * @param commands A non-null list of {@link Command}.
   * @param closePhysicalChannel True if the physical channel must be closed after the operation.
   * @since 0.3.0
   */
  static void processCommands(
      List<? extends Command> commands, ProxyReaderApi samReader, boolean closePhysicalChannel) {
    if (commands.isEmpty()) {
      return;
    }
    List<Command> cardRequestCommands = new ArrayList<>();
    for (Command command : commands) {
      if (command.isControlSamRequiredToFinalizeRequest()) {
        executeCommands(cardRequestCommands, samReader, false);
        cardRequestCommands.clear();
      }
      command.finalizeRequest();
      cardRequestCommands.add(command);
    }
    executeCommands(cardRequestCommands, samReader, closePhysicalChannel);
  }

  /**
   * Requests the execution of all commands provided by the SAM inserted in the supplied card reader
   * without finalizing it.
   *
   * @param commands A non-null list of {@link Command}.
   * @param closePhysicalChannel True if the physical channel must be closed after the operation.
   * @since 0.3.0
   */
  static void processCommandsAlreadyFinalized(
      List<? extends Command> commands, ProxyReaderApi samReader, boolean closePhysicalChannel) {
    if (commands.isEmpty()) {
      return;
    }
    executeCommands(commands, samReader, closePhysicalChannel);
  }

  /**
   * Executes the provided commands.
   *
   * @param commands The commands.
   * @param closePhysicalChannel True if the physical channel must be closed after the operation.
   */
  private static void executeCommands(
      List<? extends Command> commands, ProxyReaderApi samReader, boolean closePhysicalChannel) {
    // Retrieve the list of C-APDUs
    List<ApduRequestSpi> apduRequests = getApduRequests(commands);
    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new DtoAdapters.CardRequestAdapter(apduRequests, true);
    // Transmit the commands to the card
    CardResponseApi cardResponse =
        transmitCardRequest(
            cardRequest,
            samReader,
            closePhysicalChannel ? ChannelControl.CLOSE_AFTER : ChannelControl.KEEP_OPEN);
    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();
    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      Command command = commands.get(i);
      try {
        command.parseResponse(apduResponses.get(i));
      } catch (CommandException e) {
        throw new UnexpectedCommandStatusException(
            MSG_SAM_COMMAND_ERROR
                + "while processing responses to SAM commands: "
                + command.getCommandRef(),
            e);
      }
    }
    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
  }

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link Command}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 0.3.0
   */
  private static List<ApduRequestSpi> getApduRequests(List<? extends Command> commands) {
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
   * @param channelControl The channel control.
   * @return The card response.
   */
  private static CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest, ProxyReaderApi samReader, ChannelControl channelControl) {
    CardResponseApi cardResponse;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, channelControl);
    } catch (ReaderBrokenCommunicationException e) {
      throw new ReaderIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS, e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      cardResponse = e.getCardResponse();
    }
    return cardResponse;
  }
}
