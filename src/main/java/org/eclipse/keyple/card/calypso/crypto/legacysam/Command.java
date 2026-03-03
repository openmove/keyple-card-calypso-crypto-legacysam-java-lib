/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.keypop.card.*;

/**
 * Superclass for all SAM commands.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built {@link org.eclipse.keypop.card.spi.ApduRequestSpi},
 *   <li>the parsed {@link ApduResponseApi}.
 * </ul>
 *
 * @since 0.1.0
 */
abstract class Command {

  /**
   * This Map stores expected status that could be by default initialized with sw1=90 and sw2=00
   * (Success)
   *
   * @since 0.1.0
   */
  static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    HashMap<Integer, StatusProperties> m = new HashMap<>();
    m.put(0x6D00, new StatusProperties("Instruction unknown", IllegalParameterException.class));
    m.put(0x6E00, new StatusProperties("Class not supported", IllegalParameterException.class));
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  private final CommandRef commandRef;
  private final int le;
  private String name;
  private ApduRequestAdapter apduRequest;
  private transient ApduResponseApi apduResponse; // NOSONAR
  private final transient CommandContextDto context; // NOSONAR
  private final transient List<Command> controlSamCommands = new ArrayList<>(2); // NOSONAR

  /**
   * Constructor
   *
   * @param commandRef A command reference from the Calypso command table.
   * @param le The value of the LE field.
   * @param context The command context.
   * @since 0.1.0
   */
  Command(CommandRef commandRef, int le, CommandContextDto context) {
    this.commandRef = commandRef;
    name = commandRef.getName();
    this.le = le;
    this.context = context;
  }

  /**
   * Appends a string to the current name.
   *
   * <p>The sub name completes the name of the current command. This method must therefore only be
   * invoked conditionally (log level &gt;= debug).
   *
   * @param subName The string to append.
   * @throws NullPointerException If the request is not set.
   * @since 0.1.0
   */
  final void addSubName(String subName) {
    name = name + " - " + subName;
    apduRequest.setInfo(name);
  }

  /**
   * Returns the current command identification
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  final CommandRef getCommandRef() {
    return commandRef;
  }

  /**
   * Gets the name of this APDU command.
   *
   * @return A not empty string.
   * @since 0.1.0
   */
  final String getName() {
    return name;
  }

  /**
   * Sets the command {@link ApduRequestAdapter}.
   *
   * @param apduRequest The APDU request.
   * @since 0.1.0
   */
  final void setApduRequest(ApduRequestAdapter apduRequest) {
    this.apduRequest = apduRequest;
    this.apduRequest.setInfo(name);
  }

  /**
   * Gets the {@link ApduRequestAdapter}.
   *
   * @return Null if the request is not set.
   * @since 0.1.0
   */
  final ApduRequestAdapter getApduRequest() {
    return apduRequest;
  }

  /**
   * Gets {@link ApduResponseApi}
   *
   * @return Null if the response is not set.
   * @since 0.4.0
   */
  final ApduResponseApi getApduResponse() {
    return apduResponse;
  }

  /**
   * Returns the command context.
   *
   * @return Null if the SAM selection has not yet been made.
   * @since 0.1.0
   */
  final CommandContextDto getContext() {
    return context;
  }

  /**
   * Adds a control SAM command to be executed when finalizing.
   *
   * @param samCommand The command to be added.
   * @since 0.3.0
   */
  final void addControlSamCommand(Command samCommand) {
    controlSamCommands.add(samCommand);
  }

  /**
   * Finalize the construction of the APDU request if needed.
   *
   * @since 0.3.0
   */
  abstract void finalizeRequest();

  /**
   * Indicates the need for a control SAM to compute the data used to finalize the command.
   *
   * @return true if a control SAM is required.
   * @since 0.3.0
   */
  abstract boolean isControlSamRequiredToFinalizeRequest();

  /**
   * Parses the APDU response, updates the card image and synchronize the crypto service if it is
   * involved in the process.
   *
   * @param apduResponse The APDU response.
   * @throws CommandException if status is not successful or if the length of the response is not
   *     equal to the LE field in the request.
   * @since 0.3.0
   */
  abstract void parseResponse(ApduResponseApi apduResponse) throws CommandException;

  /**
   * Sets the response {@link ApduResponseApi} and checks the status word.
   *
   * @param apduResponse The APDU response.
   * @throws CommandException if status is not successful or if the length of the response is not
   *     equal to the LE field in the request.
   * @since 0.1.0
   */
  final void setResponseAndCheckStatus(ApduResponseApi apduResponse) throws CommandException {
    this.apduResponse = apduResponse;
    checkStatus();
  }

  /**
   * Returns the internal status table
   *
   * @return A not null reference
   * @since 0.1.0
   */
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * @return The properties of the result.
   * @throws NullPointerException If the response is not set.
   */
  private StatusProperties getStatusWordProperties() {
    return getStatusTable().get(apduResponse.getStatusWord());
  }

  /**
   * This method check the status word and if the length of the response is equal to the LE field in
   * the request.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CommandException if status is not successful or if the length of the response is not
   *     equal to the LE field in the request.
   */
  private void checkStatus() throws CommandException {

    StatusProperties props = getStatusWordProperties();
    if (props != null && props.isSuccessful()) {
      // SW is successful, then check the response length (CL-CSS-RESPLE.1)
      if (le != 0 && apduResponse.getDataOut().length != le) {
        throw new UnexpectedResponseLengthException(
            String.format(
                "Incorrect APDU response length (expected: %d, actual: %d)",
                le, apduResponse.getDataOut().length));
      }
      // SW and response length are correct.
      return;
    }
    // status word is not referenced, or not successful.

    // exception class
    Class<? extends CommandException> exceptionClass =
        props != null ? props.getExceptionClass() : null;

    // message
    String message = props != null ? props.getInformation() : "Unknown status";

    // Throw the exception
    throw buildCommandException(exceptionClass, message);
  }

  /**
   * Builds a specific APDU command exception.
   *
   * @param exceptionClass the exception class.
   * @param message The message.
   * @return A not null reference.
   * @since 0.1.0
   */
  CommandException buildCommandException(
      Class<? extends CommandException> exceptionClass, String message) {
    CommandException e;
    if (exceptionClass == AccessForbiddenException.class) {
      e = new AccessForbiddenException(message);
    } else if (exceptionClass == CounterOverflowException.class) {
      e = new CounterOverflowException(message);
    } else if (exceptionClass == DataAccessException.class) {
      e = new DataAccessException(message);
    } else if (exceptionClass == IllegalParameterException.class) {
      e = new IllegalParameterException(message);
    } else if (exceptionClass == IncorrectInputDataException.class) {
      e = new IncorrectInputDataException(message);
    } else if (exceptionClass == SecurityDataException.class) {
      e = new SecurityDataException(message);
    } else if (exceptionClass == SecurityContextException.class) {
      e = new SecurityContextException(message);
    } else {
      e = new UnknownStatusException(message);
    }
    return e;
  }

  /**
   * Executes all previously added commands for the control SAM.
   *
   * @since 0.3.0
   */
  void processControlSamCommand() {
    try {
      CommandExecutor.processCommands(controlSamCommands, context.getControlSamReader(), false);
    } finally {
      controlSamCommands.clear();
    }
  }

  /**
   * This internal class provides status word properties
   *
   * @since 0.1.0
   */
  static class StatusProperties {

    private final String information;

    private final boolean successful;

    private final Class<? extends CommandException> exceptionClass;

    /**
     * Creates a successful status.
     *
     * @param information the status information.
     * @since 0.1.0
     */
    StatusProperties(String information) {
      this.information = information;
      this.successful = true;
      this.exceptionClass = null;
    }

    /**
     * Creates an error status.<br>
     * If {@code exceptionClass} is null, then a successful status is created.
     *
     * @param information the status information.
     * @param exceptionClass the associated exception class.
     * @since 0.1.0
     */
    StatusProperties(String information, Class<? extends CommandException> exceptionClass) {
      this.information = information;
      this.successful = exceptionClass == null;
      this.exceptionClass = exceptionClass;
    }

    /**
     * Gets information
     *
     * @return A nullable reference
     * @since 0.1.0
     */
    String getInformation() {
      return information;
    }

    /**
     * Gets successful indicator
     *
     * @return The successful indicator
     * @since 0.1.0
     */
    boolean isSuccessful() {
      return successful;
    }

    /**
     * Gets Exception Class
     *
     * @return A nullable reference
     * @since 0.1.0
     */
    Class<? extends CommandException> getExceptionClass() {
      return exceptionClass;
    }
  }
}
