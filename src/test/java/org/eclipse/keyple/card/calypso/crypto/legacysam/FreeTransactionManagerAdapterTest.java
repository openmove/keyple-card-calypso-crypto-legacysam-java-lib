/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import static org.assertj.core.api.Assertions.*;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import java.util.*;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamRevocationServiceSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardReader;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.InOrder;

public final class FreeTransactionManagerAdapterTest {

  private static final String SAM_SERIAL_NUMBER = "11223344";
  private static final String CIPHER_MESSAGE = "A1A2A3A4A5A6A7A8";
  private static final String CIPHER_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
  private static final String CIPHER_MESSAGE_INCORRECT_SIGNATURE = "C1C2C3C4C5C6C7C9";
  private static final String CIPHER_MESSAGE_SIGNATURE_3_BYTES = "C1C2C3";
  private static final String PSO_MESSAGE = "A1A2A3A4A5A6A7A8A9AA";
  private static final String PSO_MESSAGE_SAM_TRACEABILITY = "B1B2B3B4B5B6B7B8B9BA";
  private static final String PSO_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
  private static final String SPECIFIC_KEY_DIVERSIFIER = "AABBCCDD";

  private static final String R_9000 = "9000";
  private static final String R_INCORRECT_SIGNATURE = "6988";

  private static final String SAM_C1_POWER_ON_DATA =
      "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;

  private static final String C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
  private static final String C_SELECT_DIVERSIFIER_SPECIFIC =
      "8014000004" + SPECIFIC_KEY_DIVERSIFIER;
  private static final String C_DATA_CIPHER_DEFAULT = "801C40000A0102" + CIPHER_MESSAGE;
  private static final String R_DATA_CIPHER_DEFAULT = CIPHER_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_COMPUTE_SIGNATURE_DEFAULT = "802A9E9A0EFF010288" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_DEFAULT = PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      "802A9E9A10FF0102480001" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
      "802A9E9A10FF0102680001" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
      PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_VERIFY_SIGNATURE_DEFAULT =
      "802A00A816FF010288" + PSO_MESSAGE + PSO_MESSAGE_SIGNATURE;
  private static final String C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      "802A00A818FF0102480001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;
  private static final String C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL =
      "802A00A818FF0102680001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;
  private static final String READ_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
  private static final String C_READ_EVENT_COUNTER_0_8 = "80BE00E100";
  private static final String R_READ_EVENT_COUNTER_0_8 =
      READ_MESSAGE_SIGNATURE
          + "1000001111111222221333331444441555551666661777771888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_EVENT_COUNTER_9_17 = "80BE00E200";
  private static final String R_READ_EVENT_COUNTER_9_17 =
      READ_MESSAGE_SIGNATURE
          + "2000002111111222222333332444442555552666662777772888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_EVENT_COUNTER_18_26 = "80BE00E300";
  private static final String R_READ_EVENT_COUNTER_18_26 =
      READ_MESSAGE_SIGNATURE
          + "3000003111113222222333333444443555553666663777773888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_EVENT_CEILING_0_8 = "80BE00B100";
  private static final String R_READ_EVENT_CEILING_0_8 =
      READ_MESSAGE_SIGNATURE
          + "2000002111112222222333332444442555552666662777772888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_EVENT_CEILING_9_17 = "80BE00B200";
  private static final String R_READ_EVENT_CEILING_9_17 =
      READ_MESSAGE_SIGNATURE
          + "2000002111111222222333332444442555552666662777772888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_EVENT_CEILING_18_26 = "80BE00B300";
  private static final String R_READ_EVENT_CEILING_18_26 =
      READ_MESSAGE_SIGNATURE
          + "3000003111113222222333333444443555553666663777773888880000E1AEC11A5CFAFF408000009000";
  private static final String C_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION = "80BC00C1020000";
  private static final String C_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT = "80BC00C2020000";
  private static final String C_READ_SYSTEM_KEY_PARAMETER_RELOADING = "80BC00C3020000";
  private static final String C_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION = "80BC00C4020000";
  private static final String R_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION =
      READ_MESSAGE_SIGNATURE
          + "E1F1401112130115161718191AC1"
          + SAM_SERIAL_NUMBER
          + "FAFF408000009000";
  private static final String R_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT =
      READ_MESSAGE_SIGNATURE
          + "FDF2402122230225262728292AC2"
          + SAM_SERIAL_NUMBER
          + "FAFF408000009000";
  private static final String R_READ_SYSTEM_KEY_PARAMETER_RELOADING =
      READ_MESSAGE_SIGNATURE
          + "E7F3403132330335363738393AC3"
          + SAM_SERIAL_NUMBER
          + "FAFF408000009000";
  private static final String R_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION =
      READ_MESSAGE_SIGNATURE
          + "FAF4404142430445464748494AC4"
          + SAM_SERIAL_NUMBER
          + "FAFF408000009000";

  private static final String CA_CERTIFICATE =
      "90010BA000000291A0000101B00100000000000000000000000000000000020B"
          + "A000000291A00100024001000000000000000000AEC8E0EA0000000020240222"
          + "00000000090100000000FF00000000000000000000000000000000000000AE0E"
          + "22FC13DA303EDEC0B02E89FC5BCDD1CED8123BAD3877C2C68BDB162C5C63DF6F"
          + "A9BE454ADD615D42D1FD4372A87F0368F0F2603C6CB12CFE3583891D2DA71185"
          + "FC9E3EB9894BD60447CA88200ED35E42AB08EC8606E0782D6005AEE9D282EE1B"
          + "98510E39D747C5070E383E8519720CD79F123B584E3DB31E05A6348369347EF0"
          + "D8C4E38A4553C26B518F235E4459534A990C680F596A19DF87C08F8124B8EA64"
          + "E1245A38BA31A2D400B36CEC7E72C5EE4EDD4C3FA7D2C8BB2A631609C341EF91"
          + "87FF80D21CF417EBE9328D07CA64F4AA40250B285559041BC64D24F5CCCC90B0"
          + "6C8EFFF0C80BADAB4D2D2ABBD21241490805A27AF1B41A282D67D61885CBDD23"
          + "F87271ABD1989C954B3146AE38AE2581DEFE8D48840F9075B9430CDD8ECB1916";

  private static final String C_GET_DATA_CA_CERTIFICATE = "80CADF43FF";

  private static final String R_GET_DATA_CA_CERTIFICATE = "DF43820180" + CA_CERTIFICATE + "9000";

  private final Map<SystemKeyType, Byte> systemKeyTypeToKifMap =
      new HashMap<SystemKeyType, Byte>() {
        {
          put(SystemKeyType.PERSONALIZATION, (byte) 0xE1);
          put(SystemKeyType.KEY_MANAGEMENT, (byte) 0xFD);
          put(SystemKeyType.RELOADING, (byte) 0xE7);
          put(SystemKeyType.AUTHENTICATION, (byte) 0xFA);
        }
      };
  private final SystemKeyType[] systemKeyTypes = SystemKeyType.values();

  private FreeTransactionManager samTransactionManager;
  private ReaderMock samReader;
  private LegacySam sam;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @Before
  public void setUp() {

    samReader = mock(ReaderMock.class);

    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    sam = new LegacySamAdapter(samCardSelectionResponse);

    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);

    samTransactionManager =
        LegacySamExtensionService.getInstance()
            .getLegacySamApiFactory()
            .createFreeTransactionManager(samReader, sam);
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

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenDataIsNull_shouldThrowIAE() {
    samTransactionManager.prepareComputeSignature(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenDataIsNotInstanceOfBasicSignatureComputationDataAdapterOrTraceableSignatureComputationDataAdapter_shouldThrowIAE() {
    TraceableSignatureComputationData data = mock(TraceableSignatureComputationData.class);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageIsNull_shouldThrowIAE() {
    BasicSignatureComputationData data = new BasicSignatureComputationDataAdapter();
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenMessageIsNull_shouldThrowIAE() {
    TraceableSignatureComputationData data = new TraceableSignatureComputationDataAdapter();
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageIsEmpty_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenMessageIsEmpty_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[209], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[207], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[209], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[15], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[208], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[16], (byte) 1, (byte) 2);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test
  public void prepareComputeSignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[208], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[206], (byte) 1, (byte) 2)
        .withSamTraceabilityMode(0, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(0);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(0);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(9);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(9);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[8], (byte) 1, (byte) 2)
            .setSignatureSize(1);
    samTransactionManager.prepareComputeSignature(data);

    data.setSignatureSize(8);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test
  public void prepareComputeSignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(1);
    samTransactionManager.prepareComputeSignature(data);

    data.setSignatureSize(8);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, SamTraceabilityMode.FULL_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, SamTraceabilityMode.FULL_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(3 * 8, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(2 * 8, SamTraceabilityMode.FULL_SERIAL_NUMBER);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareComputeSignature(data);

    data.setKeyDiversifier(new byte[8]);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareComputeSignature(data);

    data.setKeyDiversifier(new byte[8]);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareComputeSignature(data));
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_Basic_whenTryToGetSignatureButNotProcessed_shouldThrowISE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignature();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_PSO_whenTryToGetSignatureButNotProcessed_shouldThrowISE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignature();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_PSO_whenTryToGetSignedDataButNotProcessed_shouldThrowISE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignedData();
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    BasicSignatureComputationData data3 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .prepareComputeSignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data3.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    TraceableSignatureComputationData data3 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .prepareComputeSignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data3.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data3.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void prepareComputeSignature_Basic_whenSignatureSizeIsLessThan8_shouldBeSuccessful()
      throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setSignatureSize(3); // Signature size = 3
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature())
        .isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .withSamTraceabilityMode(1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER)
            .withoutBusyMode();
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .withSamTraceabilityMode(1, SamTraceabilityMode.FULL_SERIAL_NUMBER)
            .withoutBusyMode();
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenDataIsNull_shouldThrowIAE() {
    samTransactionManager.prepareVerifySignature(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenDataIsNotInstanceOfBasicSignatureVerificationDataAdapterOrTraceableSignatureVerificationDataAdapter_shouldThrowIAE() {
    TraceableSignatureVerificationData data = mock(TraceableSignatureVerificationData.class);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageIsNull_shouldThrowIAE() {
    BasicSignatureVerificationData data = new BasicSignatureVerificationDataAdapter();
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenMessageIsNull_shouldThrowIAE() {
    TraceableSignatureVerificationData data = new TraceableSignatureVerificationDataAdapter();
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageIsEmpty_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[0], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenMessageIsEmpty_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[0], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[207], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[15], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[208], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[16], new byte[8], (byte) 1, (byte) 2);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test
  public void prepareVerifySignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[1], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[208], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[206], new byte[8], (byte) 1, (byte) 2)
        .withSamTraceabilityMode(0, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureIsNull_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter().setData(new byte[10], null, (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureIsNull_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], null, (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[9], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[9], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, SamTraceabilityMode.FULL_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(3 * 8, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(2 * 8, SamTraceabilityMode.FULL_SERIAL_NUMBER, null);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareVerifySignature(data);

    data.setKeyDiversifier(new byte[8]);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareVerifySignature(data);

    data.setKeyDiversifier(new byte[8]);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test(expected = IllegalStateException.class)
  public void
      prepareVerifySignature_Basic_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
    data.isSignatureValid();
  }

  @Test(expected = IllegalStateException.class)
  public void
      prepareVerifySignature_PSO_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
    data.isSignatureValid();
  }

  @Test
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusOK_shouldBeSuccessful() {
    LegacySamRevocationServiceSpi samRevocationServiceSpi =
        mock(LegacySamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xC5C6C7))
        .thenReturn(false);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(
                8, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, samRevocationServiceSpi);
    assertThatNoException().isThrownBy(() -> samTransactionManager.prepareVerifySignature(data));
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOPartial_shouldThrowSRE() {
    LegacySamRevocationServiceSpi samRevocationServiceSpi =
        mock(LegacySamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xB5B6B7))
        .thenReturn(true);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(
                8, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, samRevocationServiceSpi);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOFull_shouldThrowSRE() {
    LegacySamRevocationServiceSpi samRevocationServiceSpi =
        mock(LegacySamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4B5"), 0xB6B7B8))
        .thenReturn(true);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(
                8, SamTraceabilityMode.FULL_SERIAL_NUMBER, samRevocationServiceSpi);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    BasicSignatureVerificationData data3 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .prepareVerifySignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_9000, R_9000, R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    TraceableSignatureVerificationData data3 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .prepareVerifySignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .withSamTraceabilityMode(1, SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER, null)
            .withoutBusyMode();
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .withSamTraceabilityMode(1, SamTraceabilityMode.FULL_SERIAL_NUMBER, null)
            .withoutBusyMode();
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void prepareVerifySignature_Basic_whenSignatureIsValid_shouldUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSignatureIsValidWithSizeLessThan8_shouldUpdateOutputData()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureIsValid_shouldUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_INCORRECT_SIGNATURE),
                (byte) 1,
                (byte) 2);
    try {
      samTransactionManager.prepareVerifySignature(data).processCommands();
      shouldHaveThrown(InvalidSignatureException.class);
    } catch (InvalidSignatureException e) {
    }
    assertThat(data.isSignatureValid()).isFalse();
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    try {
      samTransactionManager.prepareVerifySignature(data).processCommands();
      shouldHaveThrown(InvalidSignatureException.class);
    } catch (InvalidSignatureException e) {
    }
    assertThat(data.isSignatureValid()).isFalse();
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounterStatus_whenCounterIsOutOfRange_shouldThrowIAE() {
    samTransactionManager.prepareReadCounterStatus(27);
  }

  @Test
  public void prepareReadCounterStatus_whenCounterIsInRange_shouldBeSuccessful() throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_READ_EVENT_COUNTER_0_8, C_READ_EVENT_CEILING_0_8);
    CardResponseApi cardResponse =
        createCardResponse(R_READ_EVENT_COUNTER_0_8, R_READ_EVENT_CEILING_0_8);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    samTransactionManager.prepareReadCounterStatus(4);
    samTransactionManager.processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(sam.getCounter(4)).isEqualTo(0x144444);
    assertThat(sam.getCounterCeiling(4)).isEqualTo(0x244444);
  }

  @Test
  public void
      prepareReadCounterStatus_whenCounterAreInSameRecord_shouldProduceOptimizedApduRequests()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_READ_EVENT_COUNTER_0_8,
            C_READ_EVENT_CEILING_0_8,
            C_READ_EVENT_COUNTER_9_17,
            C_READ_EVENT_CEILING_9_17,
            C_READ_EVENT_COUNTER_18_26,
            C_READ_EVENT_CEILING_18_26);
    CardResponseApi cardResponse =
        createCardResponse(
            R_READ_EVENT_COUNTER_0_8,
            R_READ_EVENT_CEILING_0_8,
            R_READ_EVENT_COUNTER_9_17,
            R_READ_EVENT_CEILING_9_17,
            R_READ_EVENT_COUNTER_18_26,
            R_READ_EVENT_CEILING_18_26);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    samTransactionManager.prepareReadCounterStatus(1);
    samTransactionManager.prepareReadCounterStatus(4);
    samTransactionManager.prepareReadCounterStatus(11);
    samTransactionManager.prepareReadCounterStatus(22);
    samTransactionManager.processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(sam.getCounter(1)).isEqualTo(0x111111);
    assertThat(sam.getCounterCeiling(1)).isEqualTo(0x211111);
    assertThat(sam.getCounter(4)).isEqualTo(0x144444);
    assertThat(sam.getCounterCeiling(4)).isEqualTo(0x244444);
    assertThat(sam.getCounter(11)).isEqualTo(0x122222);
    assertThat(sam.getCounterCeiling(11)).isEqualTo(0x122222);
    assertThat(sam.getCounter(22)).isEqualTo(0x344444);
    assertThat(sam.getCounterCeiling(22)).isEqualTo(0x344444);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadSystemKeyParameters_whenSystemKeyTypeIsNull_shouldThrowIAE() {
    samTransactionManager.prepareReadSystemKeyParameters(null);
  }

  @Test
  public void prepareReadSystemKeyParameters_whenSystemKeyTypeIsNotNull_shouldBeSuccessful()
      throws Exception {
    CardRequestSpi cardRequest =
        createCardRequest(
            C_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
            C_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
            C_READ_SYSTEM_KEY_PARAMETER_RELOADING,
            C_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION);
    CardResponseApi cardResponse =
        createCardResponse(
            R_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
            R_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
            R_READ_SYSTEM_KEY_PARAMETER_RELOADING,
            R_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    samTransactionManager
        .prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION)
        .prepareReadSystemKeyParameters(SystemKeyType.KEY_MANAGEMENT)
        .prepareReadSystemKeyParameters(SystemKeyType.RELOADING)
        .prepareReadSystemKeyParameters(SystemKeyType.AUTHENTICATION)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    for (SystemKeyType type : systemKeyTypes) {
      assertThat(sam.getSystemKeyParameter(type).getKif())
          .isEqualTo(systemKeyTypeToKifMap.get(type));
      byte kvc;
      switch (type) {
        case PERSONALIZATION:
          kvc = (byte) 0xF1;
          break;
        case KEY_MANAGEMENT:
          kvc = (byte) 0xF2;
          break;
        case RELOADING:
          kvc = (byte) 0xF3;
          break;
        case AUTHENTICATION:
          kvc = (byte) 0xF4;
          break;
        default:
          throw new IllegalStateException("Unexpected key type");
      }
      assertThat(sam.getSystemKeyParameter(type).getKvc()).isEqualTo(kvc);
      assertThat(sam.getSystemKeyParameter(type).getAlgorithm()).isEqualTo((byte) 0x40);
      for (int i = 1; i <= 10; i++) {
        if (i == 4) {
          // don't test PAR4
          continue;
        }
        assertThat(sam.getSystemKeyParameter(type).getParameterValue(i))
            .isEqualTo((byte) ((type.ordinal() + 1) * 16 + i));
      }
    }
  }

  @Test
  public void exportTargetSamContextForAsyncTransaction_shouldBeSuccessful() throws Exception {
    CardRequestSpi cardRequestKeyParam =
        createCardRequest(
            C_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
            C_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
            C_READ_SYSTEM_KEY_PARAMETER_RELOADING);
    CardResponseApi cardResponseKeyParam =
        createCardResponse(
            R_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
            R_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
            R_READ_SYSTEM_KEY_PARAMETER_RELOADING);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestKeyParam)), any(ChannelControl.class)))
        .thenReturn(cardResponseKeyParam);

    CardRequestSpi cardRequestEventCounter = createCardRequest(C_READ_EVENT_COUNTER_0_8);
    CardResponseApi cardResponseEventCounter = createCardResponse(R_READ_EVENT_COUNTER_0_8);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestEventCounter)), any(ChannelControl.class)))
        .thenReturn(cardResponseEventCounter);

    String targetSamContext = samTransactionManager.exportTargetSamContextForAsyncTransaction();
    TargetSamContextDto expectedTargetSamContextDto =
        new TargetSamContextDto(sam.getSerialNumber(), false);
    expectedTargetSamContextDto
        .getSystemKeyTypeToCounterNumberMap()
        .put(SystemKeyType.PERSONALIZATION, 1);
    expectedTargetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(SystemKeyType.PERSONALIZATION, (byte) 0xF1);
    expectedTargetSamContextDto
        .getSystemKeyTypeToCounterNumberMap()
        .put(SystemKeyType.KEY_MANAGEMENT, 2);
    expectedTargetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(SystemKeyType.KEY_MANAGEMENT, (byte) 0xF2);
    expectedTargetSamContextDto
        .getSystemKeyTypeToCounterNumberMap()
        .put(SystemKeyType.RELOADING, 3);
    expectedTargetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(SystemKeyType.RELOADING, (byte) 0xF3);
    expectedTargetSamContextDto.getCounterNumberToCounterValueMap().put(1, 0x111111);
    expectedTargetSamContextDto.getCounterNumberToCounterValueMap().put(2, 0x122222);
    expectedTargetSamContextDto.getCounterNumberToCounterValueMap().put(3, 0x133333);
    String expectedTargetSamContext = JsonUtil.toJson(expectedTargetSamContextDto);
    assertThat(targetSamContext).isEqualTo(expectedTargetSamContext);
  }

  @Test
  public void processCommands_whenNoError_shouldClearCommandList() throws Exception {

    CardRequestSpi cardRequest1 =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse1 = createCardResponse(R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    CardRequestSpi cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class)))
        .thenReturn(cardResponse1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class)))
        .thenReturn(cardResponse2);

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data1).processCommands();

    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data2).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void processCommands_whenError_shouldClearCommandList() throws Exception {

    CardRequestSpi cardRequest1 =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse1 = createCardResponse(R_9000, R_INCORRECT_SIGNATURE);

    CardRequestSpi cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class)))
        .thenReturn(cardResponse1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class)))
        .thenReturn(cardResponse2);

    try {
      TraceableSignatureComputationData data1 =
          new TraceableSignatureComputationDataAdapter()
              .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
      samTransactionManager.prepareComputeSignature(data1).processCommands();
      shouldHaveThrown(UnexpectedCommandStatusException.class);
    } catch (UnexpectedCommandStatusException e) {
    }

    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data2).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareGetData_whenTagIsNull_shouldThrowIAE() {
    samTransactionManager.prepareGetData(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareGenerateCardAsymmetricKeyPair_whenKeyPairContainerIsNull_shouldThrowIAE() {
    samTransactionManager.prepareGenerateCardAsymmetricKeyPair(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeCardCertificate_whenDataIsNull_shouldThrowIAE() {
    samTransactionManager.prepareComputeCardCertificate(null);
  }
}
