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

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.CommonTransactionManagerAdapter.SAM_COMMANDS;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.CommonTransactionManagerAdapter.SAM_COMMANDS_TYPES;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import java.util.*;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.AsyncTransactionCreatorManager;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SecuritySetting;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardReader;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;

public final class AsyncTransactionCreatorManagerAdapterTest {

  private static final String SAM_SERIAL_NUMBER = "11223344";
  private static final String R_9000 = "9000";
  private static final String SAM_C1_POWER_ON_DATA =
      "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;
  private static final String C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
  private static final String C_GIVE_RANDOM_COUNTER_RELOADING_0 = "8086000008000000000000017B";
  private static final String C_GIVE_RANDOM_COUNTER_RELOADING_1 = "8086000008000000000000017C";
  private static final String C_GIVE_RANDOM_COUNTER_RELOADING_2 = "8086000008000000000000017D";
  private static final String C_SAM_DATA_CIPHER_CEILING_0 =
      "801600B81EF20000006400000000000000000000000000000000000000000000000000";
  private static final String C_SAM_DATA_CIPHER_CEILING_3 =
      "801600B81EF20300012C00000000000000000000000000000000000000000000000000";
  private static final String C_SAM_DATA_CIPHER_CEILING_RECORD_1 =
      "801600B11EF200000100000200000300000400000500000600000700000800000901FE";
  private static final String C_SAM_DATA_CIPHER_CEILING_RECORD_2 =
      "801600B21EF200000A00000B00000C00000D00000E00000F00001000001100001201FF";
  private static final String C_SAM_DATA_CIPHER_CEILING_RECORD_3 =
      "801600B31EF200001300001400001500001600001700001800001900001A00001B01FF";
  private static final String SAM_DATA_CIPHER_CEILING_0 =
      "040990EDF6C0D2F9FEF25629BEB6439B762DDCD97A90AAAD6CAACCFDD75C6209AC7ABCBF6560A7D2ACC1594441B1E32A";
  private static final String SAM_DATA_CIPHER_CEILING_3 =
      "F00B5D107C7A6BB592B82C8314634C580E533E19CFC6D3AFB6CB8C7FB853F753F50B775B2F67C9844665B4B7637B16D8";
  private static final String SAM_DATA_CIPHER_CEILING_RECORD_1 =
      "78C74465ABFC37284EA5012BA5D58994137E86FAA4D737B9A57AA977211A5B10BA4A2A2A58AC7312FA0FB23B4434F05B";
  private static final String SAM_DATA_CIPHER_CEILING_RECORD_2 =
      "9A2CCBF6952BA9D4F25ADACFFE696779FD540EE72B3B7AA487FB1D58C4633778EDBAEC9DEDF69493A93BC85DD73BF768";
  private static final String SAM_DATA_CIPHER_CEILING_RECORD_3 =
      "E141E4AF5E77074885CE850798F122B4A13CCA13FE382121E105844872EE1B628155FE70C341150F948526C17322BC78";
  private static final String R_SAM_DATA_CIPHER_CEILING_0 = SAM_DATA_CIPHER_CEILING_0 + R_9000;
  private static final String R_SAM_DATA_CIPHER_CEILING_3 = SAM_DATA_CIPHER_CEILING_3 + R_9000;
  private static final String R_SAM_DATA_CIPHER_RECORD_1 =
      SAM_DATA_CIPHER_CEILING_RECORD_1 + R_9000;
  private static final String R_SAM_DATA_CIPHER_RECORD_2 =
      SAM_DATA_CIPHER_CEILING_RECORD_2 + R_9000;
  private static final String R_SAM_DATA_CIPHER_RECORD_3 =
      SAM_DATA_CIPHER_CEILING_RECORD_3 + R_9000;
  private static final String C_STATIC_WRITE_CEILING_0 = "80D808B830" + SAM_DATA_CIPHER_CEILING_0;
  private static final String C_STATIC_WRITE_CEILING_3 = "80D808B830" + SAM_DATA_CIPHER_CEILING_3;
  private static final String C_STATIC_WRITE_CEILING_RECORD_1 =
      "80D808B130" + SAM_DATA_CIPHER_CEILING_RECORD_1;
  private static final String C_STATIC_WRITE_CEILING_RECORD_2 =
      "80D808B230" + SAM_DATA_CIPHER_CEILING_RECORD_2;
  private static final String C_STATIC_WRITE_CEILING_RECORD_3 =
      "80D808B330" + SAM_DATA_CIPHER_CEILING_RECORD_3;

  private static final String TARGET_SAM_CONTEXT =
      "{\n"
          + "\"serialNumber\": \"11223344\",\n"
          + "    \"isDynamicMode\": false,\n"
          + "    \"systemKeyTypeToCounterNumberMap\":\n"
          + "    {\n"
          + "        \"PERSONALIZATION\": \"01\",\n"
          + "        \"KEY_MANAGEMENT\": \"02\",\n"
          + "        \"RELOADING\": \"03\"\n"
          + "    },\n"
          + "    \"systemKeyTypeToKvcMap\":\n"
          + "    {\n"
          + "        \"PERSONALIZATION\": \"F1\",\n"
          + "        \"RELOADING\": \"F2\",\n"
          + "        \"KEY_MANAGEMENT\": \"F3\"\n"
          + "    },\n"
          + "    \"counterNumberToCounterValueMap\":\n"
          + "    {\n"
          + "        \"01\": \"0179\",\n"
          + "        \"02\": \"017A\",\n"
          + "        \"03\": \"017B\"\n"
          + "    }\n"
          + "}";

  private AsyncTransactionCreatorManager samTransactionManager;
  private ReaderMock samReader;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @Before
  public void setUp() {

    samReader = mock(AsyncTransactionCreatorManagerAdapterTest.ReaderMock.class);

    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);

    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    LegacySam controlSam = new LegacySamAdapter(samCardSelectionResponse);

    SecuritySetting securitySetting =
        new SecuritySettingAdapter().setControlSamResource(samReader, controlSam);

    samTransactionManager =
        LegacySamExtensionService.getInstance()
            .getLegacySamApiFactory()
            .createAsyncTransactionCreatorManager(TARGET_SAM_CONTEXT, securitySetting);
  }

  private static CardRequestSpi createCardRequest(String... apduCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    for (String apduCommand : apduCommands) {
      apduRequests.add(new ApduRequestAdapter(HexUtil.toByteArray(apduCommand)));
    }
    return new CardRequestAdapter(apduRequests, false);
  }

  private static CardResponseApi createCardResponse(String... apduCommandResponses) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    for (String apduResponse : apduCommandResponses) {
      apduResponses.add(new TestDtoAdapters.ApduResponseAdapter(HexUtil.toByteArray(apduResponse)));
    }
    return new TestDtoAdapters.CardResponseAdapter(apduResponses, true);
  }

  private static class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
    List<ApduRequestSpi> leftApduRequests;

    CardRequestMatcher(CardRequestSpi cardRequest) {
      leftApduRequests = cardRequest.getApduRequests();
    }

    @Override
    public final boolean matches(CardRequestSpi argument) {
      if (argument == null) {
        return false;
      }
      List<ApduRequestSpi> rightApduRequests = argument.getApduRequests();
      if (leftApduRequests.size() != rightApduRequests.size()) {
        return false;
      }
      Iterator<ApduRequestSpi> itLeft = leftApduRequests.iterator();
      Iterator<ApduRequestSpi> itRight = rightApduRequests.iterator();
      while (itLeft.hasNext() && itRight.hasNext()) {
        byte[] leftApdu = itLeft.next().getApdu();
        byte[] rightApdu = itRight.next().getApdu();
        if (!Arrays.equals(leftApdu, rightApdu)) {
          return false;
        }
      }
      return true;
    }
  }

  @Test(expected = UnsupportedOperationException.class)
  public void processCommands_shouldThrowUOE() {
    samTransactionManager.prepareWriteCounterCeiling(0, 100);
    samTransactionManager.processCommands();
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterCeiling_whenCeilingNumberIsOutOfRangeLow_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterCeiling(-1, 100);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterCeiling_whenCeilingNumberIsOutOfRangeHigh_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterCeiling(27, 100);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterCeiling_whenCeilingValueIsOutOfRangeLow_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterCeiling(0, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterCeiling_whenCeilingValueIsOutOfRangeHigh_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterCeiling(0, 0xFFFFFB);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterConfiguration_whenCeilingNumberIsOutOfRangeLow_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterConfiguration(
        -1, 0, CounterIncrementAccess.FREE_COUNTING_DISABLED);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterConfiguration_whenCeilingNumberIsOutOfRangeHigh_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterConfiguration(
        27, 0, CounterIncrementAccess.FREE_COUNTING_DISABLED);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterConfiguration_whenCeilingValueIsOutOfRangeLow_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterConfiguration(
        0, -1, CounterIncrementAccess.FREE_COUNTING_DISABLED);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteCounterConfiguration_whenCeilingValueIsOutOfRangeHigh_shouldThrowIAE() {
    samTransactionManager.prepareWriteCounterConfiguration(
        0, 0xFFFFFB, CounterIncrementAccess.FREE_COUNTING_DISABLED);
  }

  @Test
  public void exportCommands_whenSingleWriteArePrepared_shouldProduceJsonCommandList()
      throws Exception {
    CardRequestSpi cardRequestCipherData0 =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_GIVE_RANDOM_COUNTER_RELOADING_0, C_SAM_DATA_CIPHER_CEILING_0);
    CardResponseApi cardResponseCipherData0 =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_CEILING_0);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherData0)), any(ChannelControl.class)))
        .thenReturn(cardResponseCipherData0);

    CardRequestSpi cardRequestCipherData3 =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_GIVE_RANDOM_COUNTER_RELOADING_1, C_SAM_DATA_CIPHER_CEILING_3);
    CardResponseApi cardResponseCipherData3 =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_CEILING_3);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherData3)), any(ChannelControl.class)))
        .thenReturn(cardResponseCipherData3);

    samTransactionManager.prepareWriteCounterCeiling(0, 100);
    samTransactionManager.prepareWriteCounterCeiling(3, 300);
    String commandsJson = samTransactionManager.exportCommands();

    JsonObject jsonObject = JsonUtil.getParser().fromJson(commandsJson, JsonObject.class);

    // extract the type and command lists
    List<String> samCommandsTypes =
        JsonUtil.getParser()
            .fromJson(
                jsonObject.get(SAM_COMMANDS_TYPES).getAsJsonArray(),
                new TypeToken<ArrayList<String>>() {}.getType());
    JsonArray samCommands = jsonObject.get(SAM_COMMANDS).getAsJsonArray();

    // they should contain 2 elements
    assertThat(samCommandsTypes).hasSize(2);
    assertThat(samCommands).hasSize(2);

    for (int i = 0; i < samCommandsTypes.size(); i++) {
      // check the resulting command class
      Class<?> classOfCommand = Class.forName(samCommandsTypes.get(i));
      Command command = (Command) JsonUtil.getParser().fromJson(samCommands.get(i), classOfCommand);
      assertThat(command.getClass()).isEqualTo(CommandWriteCeilings.class);

      // check the embedded command apdu
      byte[] apduC = command.getApduRequest().getApdu();
      assertThat(apduC)
          .isEqualTo(
              HexUtil.toByteArray(i == 0 ? C_STATIC_WRITE_CEILING_0 : C_STATIC_WRITE_CEILING_3));
    }
  }

  @Test
  public void exportCommands_whenRecordWriteArePrepared_shouldProduceJsonCommandList()
      throws Exception {
    CardRequestSpi cardRequestCipherDataRec1 =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_GIVE_RANDOM_COUNTER_RELOADING_0,
            C_SAM_DATA_CIPHER_CEILING_RECORD_1);
    CardResponseApi cardResponseCipherDataRec1 =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_RECORD_1);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherDataRec1)), any(ChannelControl.class)))
        .thenReturn(cardResponseCipherDataRec1);

    CardRequestSpi cardRequestCipherDataRec2 =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_GIVE_RANDOM_COUNTER_RELOADING_1,
            C_SAM_DATA_CIPHER_CEILING_RECORD_2);
    CardResponseApi cardResponseCipherDataRec2 =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_RECORD_2);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherDataRec2)), any(ChannelControl.class)))
        .thenReturn(cardResponseCipherDataRec2);

    CardRequestSpi cardRequestCipherDataRec3 =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_GIVE_RANDOM_COUNTER_RELOADING_2,
            C_SAM_DATA_CIPHER_CEILING_RECORD_3);
    CardResponseApi cardResponseCipherDataRec3 =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_RECORD_3);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherDataRec3)), any(ChannelControl.class)))
        .thenReturn(cardResponseCipherDataRec3);

    for (int i = 0; i < 27; i++) {
      samTransactionManager.prepareWriteCounterConfiguration(
          i, i + 1, CounterIncrementAccess.FREE_COUNTING_ENABLED);
    }

    String commandsJson = samTransactionManager.exportCommands();

    JsonObject jsonObject = JsonUtil.getParser().fromJson(commandsJson, JsonObject.class);

    // extract the type and command lists
    List<String> samCommandsTypes =
        JsonUtil.getParser()
            .fromJson(
                jsonObject.get(SAM_COMMANDS_TYPES).getAsJsonArray(),
                new TypeToken<ArrayList<String>>() {}.getType());
    JsonArray samCommands = jsonObject.get(SAM_COMMANDS).getAsJsonArray();

    // they should contain 3 elements
    assertThat(samCommandsTypes).hasSize(3);
    assertThat(samCommands).hasSize(3);

    for (int i = 0; i < samCommandsTypes.size(); i++) {
      // check the resulting command class
      Class<?> classOfCommand = Class.forName(samCommandsTypes.get(i));
      Command command = (Command) JsonUtil.getParser().fromJson(samCommands.get(i), classOfCommand);
      assertThat(command.getClass()).isEqualTo(CommandWriteCeilings.class);

      // check the embedded command apdu
      byte[] apduC = command.getApduRequest().getApdu();
      switch (i) {
        case 0:
          assertThat(apduC).isEqualTo(HexUtil.toByteArray(C_STATIC_WRITE_CEILING_RECORD_1));
          break;
        case 1:
          assertThat(apduC).isEqualTo(HexUtil.toByteArray(C_STATIC_WRITE_CEILING_RECORD_2));
          break;
        case 2:
          assertThat(apduC).isEqualTo(HexUtil.toByteArray(C_STATIC_WRITE_CEILING_RECORD_3));
          break;
      }
    }
  }
}
