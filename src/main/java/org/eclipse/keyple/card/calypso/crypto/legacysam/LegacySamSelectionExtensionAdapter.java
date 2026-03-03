/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.GetDataTag;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamDynamicUnlockDataProviderSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamStaticUnlockDataProviderSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.InconsistentDataException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionExtensionSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;
import org.eclipse.keypop.card.spi.SmartCardSpi;
import org.eclipse.keypop.reader.CardReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link LegacySamSelectionExtension}.
 *
 * <p>If not specified, the SAM product type used for unlocking is {@link
 * LegacySam.ProductType#SAM_C1}.
 *
 * @since 0.1.0
 */
final class LegacySamSelectionExtensionAdapter
    implements LegacySamSelectionExtension, CardSelectionExtensionSpi {

  private static final Logger logger =
      LoggerFactory.getLogger(LegacySamSelectionExtensionAdapter.class);
  private static final int SW_NOT_LOCKED = 0x6985;
  private static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";
  private static final String MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET =
      "A setting to unlock the SAM has already been set";
  private final LegacySamAdapter legacySamAdapter;
  private final CommandContextDto context;
  private final List<Command> commands;
  private CardReader targetSamReader;
  private CommandGetChallenge commandGetChallenge;
  private UnlockSettingType unlockSettingType;
  private LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider;
  private LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider;
  private byte[] unlockDataBytes;
  private LegacySam.ProductType unlockProductType;

  private enum UnlockSettingType {
    UNSET,
    UNLOCK_DATA,
    STATIC_MODE_PROVIDER,
    DYNAMIC_MODE_PROVIDER
  }

  /**
   * Creates a {@link LegacySamSelectionExtension}.
   *
   * @since 0.1.0
   */
  LegacySamSelectionExtensionAdapter() {
    legacySamAdapter = new LegacySamAdapter(LegacySam.ProductType.SAM_C1);
    context = new CommandContextDto(legacySamAdapter, null, null);
    commands = new ArrayList<>();
    unlockSettingType = UnlockSettingType.UNSET;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {

    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<>();
    switch (unlockSettingType) {
      case UNLOCK_DATA: // NOSONAR
        // prepare the UNLOCK command and put it in first position
        CommandUnlock commandUnlock = new CommandUnlock(unlockProductType, unlockDataBytes);
        commandUnlock.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED);
        commands.add(0, commandUnlock);
        // no break
      case UNSET:
        for (Command command : commands) {
          cardSelectionApduRequests.add(command.getApduRequest());
        }
        break;
      case DYNAMIC_MODE_PROVIDER:
        // Do not add command for now when using an Unlock Data provider
        commandGetChallenge = new CommandGetChallenge(context, 8);
        cardSelectionApduRequests.add(commandGetChallenge.getApduRequest());
        break;
      default:
    }
    if (cardSelectionApduRequests.isEmpty()) {
      return new CardSelectionRequestAdapter(null);
    }
    return new CardSelectionRequestAdapter(
        new CardRequestAdapter(cardSelectionApduRequests, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponseApi)
      throws ParseException {
    try {
      legacySamAdapter.parseSelectionResponse(cardSelectionResponseApi);
      CardResponseApi cardResponse = getCardResponse(cardSelectionResponseApi);
      parseCardResponse(cardResponse);
    } catch (Exception e) {
      throw new ParseException("Invalid SAM response: " + e.getMessage(), e);
    }
    if (legacySamAdapter.getProductType() == LegacySam.ProductType.UNKNOWN
        && cardSelectionResponseApi.getSelectApplicationResponse() == null
        && cardSelectionResponseApi.getPowerOnData() == null) {
      throw new ParseException(
          "Unable to create a LegacySam: no power-on data and no FCI provided");
    }
    return legacySamAdapter;
  }

  /**
   * Returns the card response and handles the unlock command if needed.
   *
   * @param cardSelectionResponseApi The response to the initial card selection request.
   * @return The updated card response after handling the unlock command.
   * @throws AbstractApduException if an error occurs while handling the unlock command.
   */
  private CardResponseApi getCardResponse(CardSelectionResponseApi cardSelectionResponseApi)
      throws AbstractApduException, CommandException {

    CardResponseApi cardResponse = cardSelectionResponseApi.getCardResponse();

    if (unlockSettingType == UnlockSettingType.STATIC_MODE_PROVIDER
        || unlockSettingType == UnlockSettingType.DYNAMIC_MODE_PROVIDER) {

      if (targetSamReader == null) {
        throw new IllegalStateException("targetSamReader is not set");
      }

      byte[] unlockData;
      if (unlockSettingType == UnlockSettingType.STATIC_MODE_PROVIDER) {
        unlockData = staticUnlockDataProvider.getUnlockData(legacySamAdapter.getSerialNumber());
      } else {
        commandGetChallenge.parseResponse(cardResponse.getApduResponses().get(0));
        unlockData =
            dynamicUnlockDataProvider.getUnlockData(
                legacySamAdapter.getSerialNumber(), legacySamAdapter.popChallenge());
      }

      CommandUnlock unlockCommand =
          new CommandUnlock(legacySamAdapter.getProductType(), unlockData);
      unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED);
      commands.add(0, unlockCommand);

      List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<>();
      for (Command command : commands) {
        cardSelectionApduRequests.add(command.getApduRequest());
      }

      CardRequestAdapter cardRequest = new CardRequestAdapter(cardSelectionApduRequests, false);

      cardResponse =
          ((ProxyReaderApi) targetSamReader)
              .transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    }
    return cardResponse;
  }

  /**
   * Parses the APDU responses returned by the SAM to all commands.
   *
   * @param cardResponse The card response.
   */
  private void parseCardResponse(CardResponseApi cardResponse) {
    List<ApduResponseApi> apduResponses =
        cardResponse != null
            ? cardResponse.getApduResponses()
            : Collections.<ApduResponseApi>emptyList();

    if (commands.size() != apduResponses.size()) {
      throw new IllegalStateException("Mismatch in the number of requests/responses");
    }
    if (!commands.isEmpty()) {
      parseApduResponses(commands, apduResponses);
    }
  }

  /**
   * Parses the APDU responses and updates the LegacySam image.
   *
   * @param commands The list of commands that get the responses.
   * @param apduResponses The APDU responses returned by the SAM to all commands.
   */
  private static void parseApduResponses(
      List<? extends Command> commands, List<? extends ApduResponseApi> apduResponses) {
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
      try {
        commands.get(i).parseResponse(apduResponses.get(i));
      } catch (CommandException e) {
        if (e instanceof AccessForbiddenException && commands.get(i) instanceof CommandUnlock) {
          logger.warn("SAM not locked or already unlocked");
        } else {
          throw new UnexpectedCommandStatusException(
              MSG_SAM_COMMAND_ERROR
                  + "while processing responses to SAM commands: "
                  + commands.get(i).getCommandRef(),
              e);
        }
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
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension setUnlockData(
      String unlockData, LegacySam.ProductType productType) {
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    Assert.getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(unlockData.length() == 32, "unlock data length")
        .isHexString(unlockData, "unlockData")
        .notNull(productType, "productType");
    unlockProductType = productType;
    unlockDataBytes = HexUtil.toByteArray(unlockData);
    unlockSettingType = UnlockSettingType.UNLOCK_DATA;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LegacySamSelectionExtension setUnlockData(String unlockData) {
    return setUnlockData(unlockData, LegacySam.ProductType.SAM_C1);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setStaticUnlockDataProvider(
      LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider) {
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    Assert.getInstance().notNull(staticUnlockDataProvider, "staticUnlockDataProvider");
    this.staticUnlockDataProvider = staticUnlockDataProvider;
    unlockSettingType = UnlockSettingType.STATIC_MODE_PROVIDER;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setStaticUnlockDataProvider(
      LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider, CardReader targetSamReader) {
    Assert.getInstance().notNull(targetSamReader, "targetSamReader");
    this.targetSamReader = targetSamReader;
    return setStaticUnlockDataProvider(staticUnlockDataProvider);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setDynamicUnlockDataProvider(
      LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider) {
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    Assert.getInstance().notNull(dynamicUnlockDataProvider, "dynamicUnlockDataProvider");
    this.dynamicUnlockDataProvider = dynamicUnlockDataProvider;
    unlockSettingType = UnlockSettingType.DYNAMIC_MODE_PROVIDER;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setDynamicUnlockDataProvider(
      LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider, CardReader targetSamReader) {
    Assert.getInstance().notNull(targetSamReader, "targetSamReader");
    this.targetSamReader = targetSamReader;
    return setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadSamParameters() {
    commands.add(new CommandReadParameters(context));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadSystemKeyParameters(SystemKeyType systemKeyType) {
    Assert.getInstance().notNull(systemKeyType, "systemKeyType");
    commands.add(new CommandReadKeyParameters(context, systemKeyType));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadWorkKeyParameters(int recordNumber) {
    Assert.getInstance()
        .isInRange(recordNumber, MIN_KEY_RECORD_NUMBER, MAX_KEY_RECORD_NUMBER, "recordNumber");
    commands.add(new CommandReadKeyParameters(context, recordNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadWorkKeyParameters(byte kif, byte kvc) {
    commands.add(new CommandReadKeyParameters(context, kif, kvc));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadCounterStatus(int counterNumber) {
    Assert.getInstance()
        .isInRange(counterNumber, MIN_COUNTER_NUMBER, MAX_COUNTER_NUMBER, "counterNumber");
    for (Command command : commands) {
      if (command instanceof CommandReadCounter
          && ((CommandReadCounter) command).getCounterFileRecordNumber()
              == COUNTER_TO_RECORD_LOOKUP[counterNumber]) {
        // already scheduled
        return this;
      }
    }
    commands.add(new CommandReadCounter(context, COUNTER_TO_RECORD_LOOKUP[counterNumber]));
    commands.add(new CommandReadCeilings(context, COUNTER_TO_RECORD_LOOKUP[counterNumber]));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadAllCountersStatus() {
    for (int i = 0; i < 3; i++) {
      commands.add(new CommandReadCounter(context, i));
      commands.add(new CommandReadCeilings(context, i));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  public LegacySamSelectionExtension prepareGetData(GetDataTag tag) {
    Assert.getInstance().notNull(tag, "tag");
    commands.add(new CommandGetData(context, tag));
    return this;
  }

  /**
   * Schedules the execution of a "Get Challenge" command if the last command is not a "Get
   * Challenge" command.
   *
   * <p>Once this command is processed, the challenge (as an 8-byte byte array) can be access using
   * the {@link LegacySamAdapter#popChallenge()} method.
   *
   * @return The current instance.
   * @since 0.8.0
   */
  LegacySamSelectionExtension prepareGetChallengeIfNeeded() {
    if (commands.isEmpty()
        || commands.get(commands.size() - 1).getCommandRef() != CommandRef.GET_CHALLENGE) {
      commands.add(new CommandGetChallenge(context, 8));
    }
    return this;
  }

  /**
   * Provides the {@link CardReader} for communicating with the SAM during the unlocking process
   * when involving a static or a dynamic unlock data providers.
   *
   * @param targetSamReader The card reader used to communicate with the target SAM.
   * @return The current instance.
   * @since 0.5.0
   */
  LegacySamSelectionExtension setSamReader(CardReader targetSamReader) {
    this.targetSamReader = targetSamReader;
    return this;
  }
}
